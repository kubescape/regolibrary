package gitregostore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
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
	checksumsFileName                 = "checksums.txt"
	checksumsSignatureFileName        = "checksums.sigstore.json"
)

var (
	errHTTPNotFound         = errors.New("HTTP resource not found")
	ErrChecksumVerification = errors.New("checksum verification failed")
)

const (
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
	checksums, err := gs.getReleaseChecksums()
	verifyArtifacts := err == nil
	if err != nil && !errors.Is(err, errHTTPNotFound) {
		return err
	}

	for kind, storeSetterMappingFunc := range storeSetterMapping {
		var respStr string

		if verifyArtifacts {
			respStr, err = gs.getVerifiedReleaseArtifact(kind, checksums)
		} else {
			respStr, err = HttpGetter(
				gs.httpClient,
				fmt.Sprintf("%s/%s", gs.URL, gs.stripExtention(kind)),
			)
		}

		if err != nil {
			return err
		}

		if kind == frameworksJsonFileName {
			if verifyArtifacts {
				if err = gs.setFrameworksFromRelease(respStr, checksums); err != nil {
					return err
				}
			} else {
				if err = gs.setFrameworks(respStr); err != nil {
					return err
				}
			}
			continue
		}

		if err = storeSetterMappingFunc(gs, respStr); err != nil {
			return err
		}
	}

	return nil
}

func (gs *GitRegoStore) getReleaseChecksums() (map[string]string, error) {
	respStr, err := HttpGetter(
		gs.httpClient,
		fmt.Sprintf("%s/%s", gs.URL, checksumsFileName),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"error getting %s from: '%s': %w",
			checksumsFileName,
			gs.URL,
			err,
		)
	}

	signatureBundle, err := HttpGetter(
		gs.httpClient,
		fmt.Sprintf("%s/%s", gs.URL, checksumsSignatureFileName),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: error getting %s from: '%s': %s",
			ErrChecksumVerification,
			checksumsSignatureFileName,
			gs.URL,
			err,
		)
	}

	if err := verifyChecksumManifestSignature(
		[]byte(respStr),
		[]byte(signatureBundle),
	); err != nil {
		return nil, fmt.Errorf(
			"%w: error verifying %s: %w",
			ErrChecksumVerification,
			checksumsFileName,
			err,
		)
	}

	checksums, err := parseChecksums(respStr)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: error parsing %s: %w",
			ErrChecksumVerification,
			checksumsFileName,
			err,
		)
	}

	return checksums, nil
}

var fetchTrustedRootFromSigstore = root.FetchTrustedRootWithOptions

var trustedRootCache struct {
	mu       sync.RWMutex
	material *root.TrustedRoot
	ok       bool
}

func fetchTrustedRoot() (*root.TrustedRoot, error) {
	trustedRootCache.mu.RLock()
	if trustedRootCache.ok {
		material := trustedRootCache.material
		trustedRootCache.mu.RUnlock()
		return material, nil
	}
	trustedRootCache.mu.RUnlock()

	trustedRootCache.mu.Lock()
	defer trustedRootCache.mu.Unlock()

	if trustedRootCache.ok {
		return trustedRootCache.material, nil
	}

	opts := tuf.DefaultOptions()
	opts.DisableLocalCache = true

	material, err := fetchTrustedRootFromSigstore(opts)
	if err != nil {
		return nil, err
	}

	trustedRootCache.material = material
	trustedRootCache.ok = true

	return material, nil
}

func verifyChecksumManifestSignature(
	manifest []byte,
	signatureBundle []byte,
) error {
	var sigstoreBundle bundle.Bundle
	if err := sigstoreBundle.UnmarshalJSON(signatureBundle); err != nil {
		return fmt.Errorf("invalid Sigstore bundle: %w", err)
	}

	trustedRoot, err := fetchTrustedRoot()
	if err != nil {
		return fmt.Errorf("failed to fetch Sigstore trusted root: %w", err)
	}

	return verifyChecksumManifestSignatureWithTrustedMaterial(
		manifest,
		&sigstoreBundle,
		trustedRoot,
	)
}

func verifyChecksumManifestSignatureWithTrustedMaterial(
	manifest []byte,
	entity verify.SignedEntity,
	trustedMaterial root.TrustedMaterial,
) error {
	identity, err := verify.NewShortCertificateIdentity(
		"https://token.actions.githubusercontent.com",
		"",
		"",
		`^https://github\.com/kubescape/regolibrary/\.github/workflows/create-release-v2\.yaml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$`,
	)
	if err != nil {
		return fmt.Errorf("failed to create signing identity: %w", err)
	}

	verifier, err := verify.NewVerifier(
		trustedMaterial,
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("failed to create Sigstore verifier: %w", err)
	}

	_, err = verifier.Verify(
		entity,
		verify.NewPolicy(
			verify.WithArtifact(bytes.NewReader(manifest)),
			verify.WithCertificateIdentity(identity),
		),
	)
	if err != nil {
		return fmt.Errorf("Sigstore verification failed: %w", err)
	}

	return nil
}

func (gs *GitRegoStore) getVerifiedReleaseArtifact(
	filename string,
	checksums map[string]string,
) (string, error) {
	artifactName := gs.stripExtention(filename)

	expectedChecksum, ok := checksums[artifactName]
	if !ok {
		return "", fmt.Errorf(
			"%w: missing checksum for release artifact %q",
			ErrChecksumVerification,
			artifactName,
		)
	}

	respStr, err := HttpGetter(
		gs.httpClient,
		fmt.Sprintf("%s/%s", gs.URL, artifactName),
	)
	if err != nil {
		return "", fmt.Errorf(
			"error getting: %s from: '%s': %w",
			filename,
			gs.URL,
			err,
		)
	}

	if err := verifyChecksum(respStr, expectedChecksum); err != nil {
		return "", fmt.Errorf(
			"%w for %q: %w",
			ErrChecksumVerification,
			filename,
			err,
		)
	}

	return respStr, nil
}

func parseChecksums(data string) (map[string]string, error) {
	checksums := make(map[string]string)

	for lineNumber, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf(
				"invalid checksum entry on line %d",
				lineNumber+1,
			)
		}

		digest := strings.ToLower(fields[0])
		filename := fields[1]

		if len(digest) != sha256.Size*2 {
			return nil, fmt.Errorf(
				"invalid SHA-256 checksum for %q on line %d",
				filename,
				lineNumber+1,
			)
		}

		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf(
				"invalid SHA-256 checksum for %q on line %d: %w",
				filename,
				lineNumber+1,
				err,
			)
		}

		if _, exists := checksums[filename]; exists {
			return nil, fmt.Errorf(
				"duplicate checksum entry for %q",
				filename,
			)
		}

		checksums[filename] = digest
	}

	if len(checksums) == 0 {
		return nil, fmt.Errorf("checksum manifest is empty")
	}

	return checksums, nil
}

func verifyChecksum(content string, expectedChecksum string) error {
	expectedChecksum = strings.ToLower(strings.TrimSpace(expectedChecksum))

	if len(expectedChecksum) != sha256.Size*2 {
		return fmt.Errorf("invalid expected SHA-256 checksum")
	}

	if _, err := hex.DecodeString(expectedChecksum); err != nil {
		return fmt.Errorf(
			"invalid expected SHA-256 checksum: %w",
			err,
		)
	}

	actual := sha256.Sum256([]byte(content))
	actualChecksum := hex.EncodeToString(actual[:])

	if actualChecksum != expectedChecksum {
		return fmt.Errorf(
			"SHA-256 checksum mismatch: expected %s, got %s",
			expectedChecksum,
			actualChecksum,
		)
	}

	return nil
}

func (gs *GitRegoStore) setFrameworksFromRelease(
	respStr string,
	checksums map[string]string,
) error {
	frameworks := []opapolicy.Framework{}
	if err := JSONDecoder(respStr).Decode(&frameworks); err != nil {
		return err
	}

	if gs.versionHasSecurityFrameworks() {
		respStr1, err := gs.getVerifiedReleaseArtifact(
			securityFrameworksJsonFileName,
			checksums,
		)
		if err != nil {
			return err
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
		if resp.StatusCode == http.StatusNotFound {
			return respStr, errHTTPNotFound
		}
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
