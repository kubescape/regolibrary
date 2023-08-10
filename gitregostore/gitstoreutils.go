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
	securityFrameworksJsonFileName    = "security_frameworks.json"
	controlsJsonFileName              = "controls.json"
	rulesJsonFileName                 = "rules.json"
	frameworkControlRelationsFileName = "FWName_CID_CName.csv"
	ControlRuleRelationsFileName      = "ControlID_RuleName.csv"
	defaultConfigInputsFileName       = "default_config_inputs.json"
	systemPostureExceptionFileName    = "exceptions.json"

	controlIDRegex                    = `^(?:[a-z]+|[A-Z]+)(?:[\-][v]?(?:[0-9][\.]?)+)(?:[\-]?[0-9][\.]?)+$`
	earliestTagWithSecurityFrameworks = "v1.0.282-rc.0"
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

// ======================== set Objects From Release =============================================

func (gs *GitRegoStore) setObjects() error {
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
	// from a certain tag we have security frameworks
	if gs.versionHasSecurityFrameworks() {
		respStr1, err := HttpGetter(gs.httpClient, fmt.Sprintf("%s/%s", gs.URL, gs.stripExtention(securityFrameworksJsonFileName)))
		if err != nil {
			return fmt.Errorf("error getting: %s from: '%s' ,error: %s", securityFrameworksJsonFileName, gs.URL, err)
		}
		securityFrameworks := []opapolicy.Framework{}
		if err := JSONDecoder(respStr1).Decode(&securityFrameworks); err != nil {
			return err
		}
		frameworks = append(frameworks, securityFrameworks...)
	}
	gs.frameworksLock.Lock()
	defer gs.frameworksLock.Unlock()

	gs.Frameworks = frameworks
	return nil
}

func (gs *GitRegoStore) versionHasSecurityFrameworks() bool {
	// check if tag contains numbers
	if !hasNumbers(gs.Tag) {
		return true
	}
	tag := strings.Split(gs.Tag, "/")[1]
	return tag >= earliestTagWithSecurityFrameworks
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

// Set controls set the controls list and attackTrackControls in gitRegoStore
func (gs *GitRegoStore) setControls(respStr string) error {
	controls := []opapolicy.Control{}
	if err := JSONDecoder(respStr).Decode(&controls); err != nil {
		return err
	}
	gs.controlsLock.Lock()
	defer gs.controlsLock.Unlock()

	gs.Controls = controls
	gs.setAttackTracksControls()
	return nil
}

// GetAttackTracksControls sets controls that are related to attack tracks
func (gs *GitRegoStore) setAttackTracksControls() error {
	allAttackTrackControls := []opapolicy.Control{}

	for i, control := range gs.Controls {
		controlCategories := control.GetAllAttackTrackCategories()
		if controlCategories != nil && len(controlCategories) > 0 {
			allAttackTrackControls = append(allAttackTrackControls, gs.Controls[i])
		}
	}
	gs.attackTrackControlsLock.Lock()
	defer gs.attackTrackControlsLock.Unlock()
	gs.AttackTrackControls = allAttackTrackControls

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

func hasNumbers(s string) bool {
	for _, char := range s {
		if char >= '0' && char <= '9' {
			return true
		}
	}
	return false
}
