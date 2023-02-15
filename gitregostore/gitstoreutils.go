package gitregostore

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/go-gota/gota/dataframe"
	opapolicy "github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"go.uber.org/zap"
)

type storeSetter func(*GitRegoStore, string) error

const (
	attackTracksJsonFileName          = "attack_tracks.json"
	attackTracksPathPrefix            = "attack-tracks"
	frameworksJsonFileName            = "frameworks.json"
	controlsJsonFileName              = "controls.json"
	rulesJsonFileName                 = "rules.json"
	frameworkControlRelationsFileName = "FWName_CID_CName.csv"
	ControlRuleRelationsFileName      = "ControlID_RuleName.csv"
	defaultConfigInputsFileName       = "default_config_inputs.json"
	systemPostureExceptionFileName    = "exceptions.json"

	controlIDRegex = `^(?:[a-z]+|[A-Z]+)(?:[\-][v]?(?:[0-9][\.]?)+)(?:[\-]?[0-9][\.]?)+$`
)

var (
	controlIDRegexCompiled *regexp.Regexp
	compileRexOnce         sync.Once

	storeSetterMapping = map[string]storeSetter{
		attackTracksJsonFileName:          (*GitRegoStore).setAttackTracks,
		frameworksJsonFileName:            (*GitRegoStore).setFrameworks,
		controlsJsonFileName:              (*GitRegoStore).setControls,
		rulesJsonFileName:                 (*GitRegoStore).setRules,
		frameworkControlRelationsFileName: (*GitRegoStore).setFrameworkControlRelations,
		ControlRuleRelationsFileName:      (*GitRegoStore).setControlRuleRelations,
		defaultConfigInputsFileName:       (*GitRegoStore).setDefaultConfigInputs,
		systemPostureExceptionFileName:    (*GitRegoStore).setSystemPostureExceptionPolicies,
	}
)

type InnerTree []struct {
	PATH string `json:"path"`
}
type Tree struct {
	TREE InnerTree `json:"tree"`
}

func (gs *GitRegoStore) stripExtention(filename string) string {
	if gs.StripFilesExtension {
		return strings.Split(filename, ".")[0]
	}
	return filename
}

// func setURL()
func (gs *GitRegoStore) setURL() {
	if p, err := url.JoinPath(gs.BaseUrl, gs.Owner, gs.Repository, gs.Branch, gs.Path, gs.Tag); err == nil {
		gs.URL = p
	}
}

func (gs *GitRegoStore) setObjects() error {
	// This condition to support old reading files from repo.
	// Once dev helm parameters are updated to new releaseDev folder, this condition should be removed.
	if gs.Path == "git/trees" {
		return gs.setObjectsFromRepoOnce()
	}
	return gs.setObjectsFromReleaseLoop()
}

// DEPRECATED
func (gs *GitRegoStore) setObjectsFromRepoOnce() error {

	url := gs.BaseUrl + "/" + gs.Owner + "/" + gs.Repository + "/" + gs.Path + "/" + gs.Branch + "?recursive=1"

	body, err := HttpGetter(gs.httpClient, url)
	if err != nil {
		return err
	}
	var trees Tree
	err = json.Unmarshal([]byte(body), &trees)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body from '%s', reason: %s", gs.URL, err.Error())
	}

	//use a clone of the store for the update to avoid long lock time
	gsClone := newGitRegoStore(gs.BaseUrl, gs.Owner, gs.Repository, gs.Path, gs.Tag, gs.Branch, gs.FrequencyPullFromGitMinutes)

	// use only json files from relevant dirs
	for _, path := range trees.TREE {
		rawDataPath := "https://raw.githubusercontent.com/" + gsClone.Owner + "/" + gsClone.Repository + "/" + gsClone.Branch + "/" + path.PATH

		if strings.HasPrefix(path.PATH, strings.Replace(rulesJsonFileName, ".json", "/", -1)) && strings.HasSuffix(path.PATH, ".json") && !strings.Contains(path.PATH, "/test/") {
			respStr, err := HttpGetter(gsClone.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			if err := gsClone.setRulesWithRawRego(respStr, rawDataPath); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set rule %s\n", zap.String("path", rawDataPath))
				return err
			}
		} else if strings.HasPrefix(path.PATH, strings.Replace(controlsJsonFileName, ".json", "/", -1)) && strings.HasSuffix(path.PATH, ".json") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			if err := gsClone.setControl(respStr); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set control %s\n", zap.String("path", rawDataPath))
				return err
			}
		} else if strings.HasPrefix(path.PATH, strings.Replace(frameworksJsonFileName, ".json", "/", -1)) && strings.HasSuffix(path.PATH, ".json") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			if err := gsClone.setFramework(respStr); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set framework %s\n", zap.String("path", rawDataPath))
				return err
			}
		} else if strings.HasPrefix(path.PATH, attackTracksPathPrefix+"/") && strings.HasSuffix(path.PATH, ".json") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return nil
			}
			if err := gsClone.setAttackTrack(respStr); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set attack track %s\n", zap.String("path", rawDataPath))
				return nil
			}
		} else if strings.HasPrefix(path.PATH, defaultConfigInputsFileName) && strings.HasSuffix(path.PATH, ".json") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			if err := gsClone.setDefaultConfigInputs(respStr); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set DefaultConfigInputs %s\n", zap.String("path", rawDataPath))
				return err
			}
		} else if strings.HasPrefix(path.PATH, systemPostureExceptionFileName+"/") && strings.HasSuffix(path.PATH, ".json") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			if err := gsClone.setSystemPostureExceptionPolicy(respStr); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set setSystemPostureExceptionPolicy %s\n", zap.String("path", rawDataPath))
				return err
			}
		} else if strings.HasSuffix(path.PATH, ControlRuleRelationsFileName) {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			gsClone.setControlRuleRelations(respStr)
		} else if strings.HasSuffix(path.PATH, frameworkControlRelationsFileName) {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			gsClone.setFrameworkControlRelations(respStr)
		}
	}

	gs.copyData(gsClone)
	return nil
}

func (gs *GitRegoStore) setFramework(respStr string) error {
	framework := &opapolicy.Framework{}
	if err := JSONDecoder(respStr).Decode(framework); err != nil {
		return err
	}
	gs.Frameworks = append(gs.Frameworks, *framework)
	return nil
}

func (gs *GitRegoStore) setAttackTrack(respStr string) error {
	attackTrack := &v1alpha1.AttackTrack{}
	if err := JSONDecoder(respStr).Decode(attackTrack); err != nil {
		return err
	}
	gs.AttackTracks = append(gs.AttackTracks, *attackTrack)
	return nil
}

func (gs *GitRegoStore) setSystemPostureExceptionPolicy(respStr string) error {
	exceptions := []armotypes.PostureExceptionPolicy{}
	if err := JSONDecoder(respStr).Decode(&exceptions); err != nil {
		return err
	}

	gs.SystemPostureExceptionPolicies = append(gs.SystemPostureExceptionPolicies, exceptions...)
	return nil
}

func (gs *GitRegoStore) setControl(respStr string) error {
	control := &opapolicy.Control{}
	if err := JSONDecoder(respStr).Decode(control); err != nil {
		return err
	}
	gs.Controls = append(gs.Controls, *control)
	return nil
}

func (gs *GitRegoStore) setRulesWithRawRego(respStr string, path string) error {
	rule := &opapolicy.PolicyRule{}
	rawRego, err := gs.getRulesWithRawRego(rule, respStr, path)
	if err != nil {
		return err
	}
	filterRego, err := gs.getRulesWithFilterRego(rule, respStr, path)
	if err != nil && !strings.Contains(err.Error(), "404 Not Found") {
		return err
	}
	rule.Rule = rawRego
	rule.ResourceEnumerator = filterRego
	gs.Rules = append(gs.Rules, *rule)
	return nil
}

func (gs *GitRegoStore) getRulesWithRawRego(rule *opapolicy.PolicyRule, respStr string, path string) (string, error) {
	if err := JSONDecoder(respStr).Decode(rule); err != nil {
		return "", err
	}
	rawRegoPath := path[:strings.LastIndex(path, "/")] + "/raw.rego"
	respString, err := HttpGetter(gs.httpClient, rawRegoPath)
	if err != nil {
		return "", err
	}
	return respString, nil
}

func (gs *GitRegoStore) getRulesWithFilterRego(rule *opapolicy.PolicyRule, respStr string, path string) (string, error) {
	if err := JSONDecoder(respStr).Decode(rule); err != nil {
		return "", err
	}
	rawRegoPath := path[:strings.LastIndex(path, "/")] + "/filter.rego"
	respString, err := HttpGetter(gs.httpClient, rawRegoPath)
	if err != nil {
		return "", err
	}
	return respString, nil
}

// ======================== set Objects From Release =============================================

func (gs *GitRegoStore) setObjectsFromReleaseLoop() error {
	var wg sync.WaitGroup
	wg.Add(1)
	var e error
	go func() {
		f := true
		for {
			if err := gs.setObjectsFromReleaseOnce(); err != nil {
				e = err
			}
			if f {
				wg.Done() // first update to done
				f = false
			}
			if !gs.Watch {
				return
			}
			time.Sleep(time.Duration(gs.FrequencyPullFromGitMinutes) * time.Minute)
		}
	}()
	wg.Wait()
	return e
}

func (gs *GitRegoStore) setObjectsFromReleaseOnce() error {

	for kind, storeSetterMappingFunc := range storeSetterMapping {
		respStr, err := HttpGetter(gs.httpClient, fmt.Sprintf("%s/%s", gs.URL, gs.stripExtention(kind)))
		if err != nil {
			return fmt.Errorf("error getting: %s from: '%s' ,error: %s", kind, gs.URL, err)
		}
		if err = storeSetterMappingFunc(gs, respStr); err != nil {
			return err
		}
	}
	return nil
}

func (gs *GitRegoStore) setFrameworks(respStr string) error {
	frameworks := []opapolicy.Framework{}
	if err := JSONDecoder(respStr).Decode(&frameworks); err != nil {
		return err
	}
	gs.frameworksLock.Lock()
	defer gs.frameworksLock.Unlock()

	gs.Frameworks = frameworks
	return nil
}

func (gs *GitRegoStore) setAttackTracks(respStr string) error {
	attacktracks := []v1alpha1.AttackTrack{}
	if err := JSONDecoder(respStr).Decode(&attacktracks); err != nil {
		return err
	}
	gs.attackTracksLock.Lock()
	defer gs.attackTracksLock.Unlock()

	gs.AttackTracks = attacktracks
	return nil
}

func (gs *GitRegoStore) setControls(respStr string) error {
	controls := []opapolicy.Control{}
	if err := JSONDecoder(respStr).Decode(&controls); err != nil {
		return err
	}
	gs.controlsLock.Lock()
	defer gs.controlsLock.Unlock()

	gs.Controls = controls
	return nil
}

func (gs *GitRegoStore) setRules(respStr string) error {
	rules := &[]opapolicy.PolicyRule{}
	if err := JSONDecoder(respStr).Decode(rules); err != nil {
		return err
	}
	gs.rulesLock.Lock()
	defer gs.rulesLock.Unlock()

	gs.Rules = *rules
	return nil
}
func (gs *GitRegoStore) setDefaultConfigInputs(respStr string) error {
	defaultConfigInputs := armotypes.CustomerConfig{}
	if err := JSONDecoder(respStr).Decode(&defaultConfigInputs); err != nil {
		return err
	}
	gs.DefaultConfigInputsLock.Lock()
	defer gs.DefaultConfigInputsLock.Unlock()

	gs.DefaultConfigInputs = defaultConfigInputs
	return nil
}

func (gs *GitRegoStore) setSystemPostureExceptionPolicies(respStr string) error {
	exceptions := []armotypes.PostureExceptionPolicy{}
	if err := JSONDecoder(respStr).Decode(&exceptions); err != nil {
		return err
	}
	gs.systemPostureExceptionPoliciesLock.Lock()
	defer gs.systemPostureExceptionPoliciesLock.Unlock()

	gs.SystemPostureExceptionPolicies = exceptions
	return nil
}

func (gs *GitRegoStore) setFrameworkControlRelations(respStr string) error {
	df := dataframe.ReadCSV(strings.NewReader(respStr))

	gs.frameworkRelationsLock.Lock()
	gs.FrameworkControlRelations = df
	gs.frameworkRelationsLock.Unlock()

	return nil
}

func (gs *GitRegoStore) setControlRuleRelations(respStr string) error {
	df := dataframe.ReadCSV(strings.NewReader(respStr))

	gs.controlRelationsLock.Lock()
	gs.ControlRuleRelations = df
	gs.controlRelationsLock.Unlock()

	return nil
}

func (gs *GitRegoStore) lockAll() {
	gs.frameworksLock.Lock()
	gs.controlsLock.Lock()
	gs.controlRelationsLock.Lock()
	gs.frameworkRelationsLock.Lock()
	gs.rulesLock.Lock()
	gs.attackTracksLock.Lock()
	gs.systemPostureExceptionPoliciesLock.Lock()
	gs.DefaultConfigInputsLock.Lock()
}

func (gs *GitRegoStore) rLockAll() {
	gs.frameworksLock.RLock()
	gs.controlsLock.RLock()
	gs.controlRelationsLock.RLock()
	gs.frameworkRelationsLock.RLock()
	gs.rulesLock.RLock()
	gs.attackTracksLock.RLock()
	gs.systemPostureExceptionPoliciesLock.RLock()
	gs.DefaultConfigInputsLock.RLock()
}

func (gs *GitRegoStore) unlockAll() {
	// unlock acquired mutexes in the reverse order of locking
	gs.DefaultConfigInputsLock.Unlock()
	gs.systemPostureExceptionPoliciesLock.Unlock()
	gs.attackTracksLock.Unlock()
	gs.rulesLock.Unlock()
	gs.frameworkRelationsLock.Unlock()
	gs.controlRelationsLock.Unlock()
	gs.controlsLock.Unlock()
	gs.frameworksLock.Unlock()
}

func (gs *GitRegoStore) rUnlockAll() {
	// unlock acquired mutexes in the reverse order of locking
	gs.DefaultConfigInputsLock.RUnlock()
	gs.systemPostureExceptionPoliciesLock.RUnlock()
	gs.frameworkRelationsLock.RUnlock()
	gs.attackTracksLock.RUnlock()
	gs.rulesLock.RUnlock()
	gs.controlRelationsLock.RUnlock()
	gs.controlsLock.RUnlock()
	gs.frameworksLock.RUnlock()
}

func (gs *GitRegoStore) copyData(other *GitRegoStore) {
	other.rLockAll()
	defer other.rUnlockAll()
	gs.lockAll()
	defer gs.unlockAll()

	gs.Frameworks = other.Frameworks
	gs.Controls = other.Controls
	gs.Rules = other.Rules
	gs.AttackTracks = other.AttackTracks
	gs.SystemPostureExceptionPolicies = other.SystemPostureExceptionPolicies
	gs.DefaultConfigInputs = other.DefaultConfigInputs
	gs.ControlRuleRelations = other.ControlRuleRelations
	gs.FrameworkControlRelations = other.FrameworkControlRelations
}

// JSONDecoder returns JSON decoder for given string
func JSONDecoder(origin string) *json.Decoder {
	dec := json.NewDecoder(strings.NewReader(origin))
	dec.UseNumber()
	return dec
}

func HttpGetter(httpClient *http.Client, fullURL string) (string, error) {
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	respStr, err := HTTPRespToString(resp)
	if err != nil {
		return "", err
	}
	return respStr, nil
}

// HTTPRespToString parses the body as string and checks the HTTP status code, it closes the body reader at the end
// TODO: FIX BUG: status code is not being checked when the body is empty
func HTTPRespToString(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	strBuilder := strings.Builder{}
	defer resp.Body.Close()
	if resp.ContentLength > 0 {
		strBuilder.Grow(int(resp.ContentLength))
	}
	bytesNum, err := io.Copy(&strBuilder, resp.Body)
	respStr := strBuilder.String()
	if err != nil {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		return "", fmt.Errorf("HTTP request failed. URL: '%s', Read-ERROR: '%s', HTTP-CODE: '%s', BODY(top): '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), err, resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		err = fmt.Errorf("HTTP request failed. URL: '%s', HTTP-ERROR: '%s', BODY: '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	zap.L().Debug("In HTTPRespToString - request end succesfully",
		zap.String("URL", resp.Request.URL.String()), zap.Int("contentLength", int(resp.ContentLength)))

	return respStr, err
}

func isControlID(c string) bool {
	compileRexOnce.Do(func() {
		// compile regex only once
		controlIDRegexCompiled = regexp.MustCompile(controlIDRegex)
	})

	return controlIDRegexCompiled.MatchString(c)
}
