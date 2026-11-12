package gitregostore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
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

// DefaultRequestTimeout bounds every single HTTP request made while pulling a release.
// It never extends a deadline already carried by the caller's context.
const DefaultRequestTimeout = 60 * time.Second

// releaseArtifacts holds the raw content of a fully downloaded (and, when possible, verified) release.
// Nothing is applied to the store until every artifact has been downloaded.
type releaseArtifacts struct {
	files              map[string]string
	securityFrameworks string
	hasSecurity        bool
}

func (gs *GitRegoStore) setObjects(ctx context.Context) error {
	err := gs.setObjectsFromReleaseOnce(ctx)
	if gs.Watch {
		go gs.watchRelease(ctx)
	}
	return err
}

// watchRelease periodically pulls the release again until ctx is done.
func (gs *GitRegoStore) watchRelease(ctx context.Context) {
	interval := time.Duration(gs.FrequencyPullFromGitMinutes) * time.Minute
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = gs.setObjectsFromReleaseOnce(ctx)
		}
	}
}

func (gs *GitRegoStore) setObjectsFromReleaseOnce(ctx context.Context) error {
	artifacts, err := gs.downloadRelease(ctx)
	if err != nil {
		return err
	}

	return gs.applyRelease(artifacts)
}

// downloadRelease downloads every release artifact without touching the store state.
func (gs *GitRegoStore) downloadRelease(ctx context.Context) (*releaseArtifacts, error) {
	checksums, err := gs.getReleaseChecksums(ctx)
	verifyArtifacts := err == nil
	if err != nil && !errors.Is(err, errHTTPNotFound) {
		return nil, err
	}

	fetch := func(kind string) (string, error) {
		if verifyArtifacts {
			return gs.getVerifiedReleaseArtifact(ctx, kind, checksums)
		}
		return gs.httpGet(ctx, fmt.Sprintf("%s/%s", gs.URL, gs.stripExtention(kind)))
	}

	artifacts := &releaseArtifacts{files: make(map[string]string, len(storeSetterMapping)+1)}
	kinds := []string{frameworksJsonFileName}
	for kind := range storeSetterMapping {
		kinds = append(kinds, kind)
	}

	for _, kind := range kinds {
		respStr, err := fetch(kind)
		if err != nil {
			return nil, err
		}
		artifacts.files[kind] = respStr
	}

	// from a certain tag we have security frameworks
	if gs.versionHasSecurityFrameworks() {
		respStr, err := fetch(securityFrameworksJsonFileName)
		if err != nil {
			return nil, wrapDownloadError(
				fmt.Sprintf("error getting: %s from: '%s'", securityFrameworksJsonFileName, gs.URL),
				err,
			)
		}
		artifacts.securityFrameworks = respStr
		artifacts.hasSecurity = true
	}

	return artifacts, nil
}

// applyRelease decodes and prepares every downloaded artifact in a staging store and publishes the result to
// gs only if all of them succeeded. On error gs is left completely unchanged.
func (gs *GitRegoStore) applyRelease(artifacts *releaseArtifacts) error {
	staged, err := stageRelease(artifacts)
	if err != nil {
		return err
	}

	gs.publishRelease(staged)
	return nil
}

// stageRelease prepares the complete new state in a private store that no other goroutine can see.
// Artifacts are processed in a fixed order, so the reported error does not depend on map iteration order.
func stageRelease(artifacts *releaseArtifacts) (*GitRegoStore, error) {
	staged := &GitRegoStore{}

	if respStr, ok := artifacts.files[frameworksJsonFileName]; ok {
		if err := staged.setFrameworks(respStr, artifacts.securityFrameworks, artifacts.hasSecurity); err != nil {
			return nil, err
		}
	}

	kinds := make([]string, 0, len(storeSetterMapping))
	for kind := range storeSetterMapping {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)

	for _, kind := range kinds {
		respStr, ok := artifacts.files[kind]
		if !ok {
			continue
		}
		if err := storeSetterMapping[kind](staged, respStr); err != nil {
			return nil, fmt.Errorf("error preparing %s: %w", kind, err)
		}
	}

	return staged, nil
}

// publishRelease swaps the staged state into gs. Every lock protecting the published fields is held for the
// whole swap, so a reader holding any of them (even several at once) sees either the old or the new state.
// Locks are taken in the order readers already nest them (frameworks, controls, rules, relations), which
// avoids lock-order inversions.
func (gs *GitRegoStore) publishRelease(staged *GitRegoStore) {
	gs.frameworksLock.Lock()
	defer gs.frameworksLock.Unlock()
	gs.controlsLock.Lock()
	defer gs.controlsLock.Unlock()
	gs.attackTrackControlsLock.Lock()
	defer gs.attackTrackControlsLock.Unlock()
	gs.rulesLock.Lock()
	defer gs.rulesLock.Unlock()
	gs.controlRelationsLock.Lock()
	defer gs.controlRelationsLock.Unlock()
	gs.frameworkRelationsLock.Lock()
	defer gs.frameworkRelationsLock.Unlock()
	gs.attackTracksLock.Lock()
	defer gs.attackTracksLock.Unlock()
	gs.DefaultConfigInputsLock.Lock()
	defer gs.DefaultConfigInputsLock.Unlock()
	gs.systemPostureExceptionPoliciesLock.Lock()
	defer gs.systemPostureExceptionPoliciesLock.Unlock()

	gs.Frameworks = staged.Frameworks
	gs.Controls = staged.Controls
	gs.AttackTrackControls = staged.AttackTrackControls
	gs.Rules = staged.Rules
	gs.ControlRuleRelations = staged.ControlRuleRelations
	gs.FrameworkControlRelations = staged.FrameworkControlRelations
	gs.AttackTracks = staged.AttackTracks
	gs.DefaultConfigInputs = staged.DefaultConfigInputs
	gs.SystemPostureExceptionPolicies = staged.SystemPostureExceptionPolicies
}

// httpGet issues a context-aware GET using the store's HTTP client and request timeout.
func (gs *GitRegoStore) httpGet(ctx context.Context, fullURL string) (string, error) {
	timeout := gs.requestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	return httpGetter(ctx, gs.httpClient, fullURL, timeout)
}

// isContextError reports whether err was caused by cancellation or a deadline.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// wrapDownloadError adds context to a download error. The cause is wrapped (so callers can use errors.Is
// with context.Canceled / context.DeadlineExceeded) only when it is a cancellation or timeout; other causes
// keep their previous, flattened form so that e.g. errHTTPNotFound is not accidentally propagated.
func wrapDownloadError(msg string, err error) error {
	if isContextError(err) {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return fmt.Errorf("%s: %s", msg, err)
}

func (gs *GitRegoStore) getReleaseChecksums(ctx context.Context) (map[string]string, error) {
	respStr, err := gs.httpGet(
		ctx,
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

	signatureBundle, err := gs.httpGet(
		ctx,
		fmt.Sprintf("%s/%s", gs.URL, checksumsSignatureFileName),
	)
	if err != nil {
		if isContextError(err) {
			return nil, fmt.Errorf(
				"error getting %s from: '%s': %w",
				checksumsSignatureFileName,
				gs.URL,
				err,
			)
		}
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

var fetchTrustedRootFromSigstore = root.NewLiveTrustedRoot

var trustedRootCache struct {
	mu       sync.RWMutex
	material *root.LiveTrustedRoot
}

func fetchTrustedRoot() (*root.LiveTrustedRoot, error) {
	trustedRootCache.mu.RLock()
	if trustedRootCache.material != nil {
		material := trustedRootCache.material
		trustedRootCache.mu.RUnlock()
		return material, nil
	}
	trustedRootCache.mu.RUnlock()

	trustedRootCache.mu.Lock()
	defer trustedRootCache.mu.Unlock()

	if trustedRootCache.material != nil {
		return trustedRootCache.material, nil
	}

	opts := tuf.DefaultOptions()
	opts.DisableLocalCache = true

	material, err := fetchTrustedRootFromSigstore(opts)
	if err != nil {
		return nil, err
	}

	trustedRootCache.material = material

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
	ctx context.Context,
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

	respStr, err := gs.httpGet(
		ctx,
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

func (gs *GitRegoStore) setFrameworks(respStr, securityRespStr string, hasSecurity bool) error {
	frameworks := []opapolicy.Framework{}
	if err := JSONDecoder(respStr).Decode(&frameworks); err != nil {
		return err
	}
	if hasSecurity {
		securityFrameworks := []opapolicy.Framework{}
		if err := JSONDecoder(securityRespStr).Decode(&securityFrameworks); err != nil {
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
	if df.Err != nil {
		return df.Err
	}

	gs.frameworkRelationsLock.Lock()
	gs.FrameworkControlRelations = df
	gs.frameworkRelationsLock.Unlock()

	return nil
}

func (gs *GitRegoStore) setControlRuleRelations(respStr string) error {
	df := dataframe.ReadCSV(strings.NewReader(respStr))
	if df.Err != nil {
		return df.Err
	}

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

// HttpGetter performs a GET request bounded by DefaultRequestTimeout.
// Use HttpGetterWithContext to make the request cancellable by the caller.
func HttpGetter(httpClient *http.Client, fullURL string) (string, error) {
	return HttpGetterWithContext(context.Background(), httpClient, fullURL)
}

// HttpGetterWithContext performs a GET request that is aborted when ctx is cancelled or its deadline expires.
// The request is additionally bounded by DefaultRequestTimeout, which never extends an earlier ctx deadline.
// Cancellation and timeout errors wrap context.Canceled / context.DeadlineExceeded.
func HttpGetterWithContext(ctx context.Context, httpClient *http.Client, fullURL string) (string, error) {
	return httpGetter(ctx, httpClient, fullURL, DefaultRequestTimeout)
}

func httpGetter(ctx context.Context, httpClient *http.Client, fullURL string, timeout time.Duration) (string, error) {
	// The timeout covers reading the whole body, so cancel only after HTTPRespToString returns.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
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
		return "", fmt.Errorf("HTTP request failed. URL: '%s', Read-ERROR: '%w', HTTP-CODE: '%s', BODY(top): '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), err, resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
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
