package gitregostore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

type frameworkManifest struct {
	Name           string                       `json:"name"`
	ScanningScope  reporthandling.ScanningScope `json:"scanningScope"`
	ActiveControls []struct {
		ControlID string `json:"controlID"`
	} `json:"activeControls"`
}

type controlManifest struct {
	ControlID     string                       `json:"controlID"`
	RulesNames    []string                     `json:"rulesNames"`
	ScanningScope reporthandling.ScanningScope `json:"scanningScope"`
}

type agentRuntimeControlContract struct {
	rule      string
	resources []string
}

func TestAgentRuntimeFrameworkContract(t *testing.T) {
	frameworkFile, err := os.ReadFile(filepath.Join("..", "frameworks", "agent-runtime-hardening.json"))
	require.NoError(t, err)

	var framework frameworkManifest
	require.NoError(t, json.Unmarshal(frameworkFile, &framework))
	require.Equal(t, "AgentRuntimeHardening", framework.Name)
	require.ElementsMatch(t, []reporthandling.ScanningScopeType{
		reporthandling.ScopeCluster,
		reporthandling.ScopeFile,
	}, framework.ScanningScope.Matches)

	expected := map[string]agentRuntimeControlContract{
		"C-0297": {"agent-sandbox-hardened-runtime-class", []string{"Sandbox", "SandboxTemplate"}},
		"C-0309": {"agent-sandbox-service-account-token", []string{"Sandbox", "SandboxTemplate"}},
		"C-0311": {"agent-sandbox-container-limits", []string{"Sandbox", "SandboxTemplate"}},
		"C-0312": {"agent-runtime-image-digests", []string{"Sandbox", "SandboxTemplate", "WorkerPool"}},
		"C-0313": {"agent-runtime-image-registries", []string{"Sandbox", "SandboxTemplate", "WorkerPool"}},
		"C-0314": {"agent-sandbox-managed-networking", []string{"SandboxTemplate"}},
		"C-0315": {"agent-sandbox-strict-egress", []string{"SandboxTemplate"}},
		"C-0316": {"agent-sandbox-claim-overrides", []string{"SandboxTemplate"}},
		"C-0317": {"worker-pod-resource-ceilings", []string{"WorkerPool"}},
	}

	actualControls := make(map[string]struct{}, len(framework.ActiveControls))
	for _, activeControl := range framework.ActiveControls {
		actualControls[activeControl.ControlID] = struct{}{}
	}
	require.Len(t, framework.ActiveControls, len(expected))
	require.Equal(t, expectedControlIDs(expected), actualControls)

	for controlID, want := range expected {
		t.Run(controlID, func(t *testing.T) {
			control := readAgentRuntimeControl(t, controlID)
			require.ElementsMatch(t, []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeFile,
			}, control.ScanningScope.Matches)
			require.Equal(t, []string{want.rule}, control.RulesNames)

			rule := readAgentRuntimeRule(t, want.rule)
			actualResources := make([]string, 0)
			for _, match := range rule.Match {
				actualResources = append(actualResources, match.Resources...)
			}
			require.ElementsMatch(t, want.resources, actualResources)
		})
	}
}

func expectedControlIDs(expected map[string]agentRuntimeControlContract) map[string]struct{} {
	ids := make(map[string]struct{}, len(expected))
	for controlID := range expected {
		ids[controlID] = struct{}{}
	}
	return ids
}

func readAgentRuntimeControl(t *testing.T, controlID string) controlManifest {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "controls", "*.json"))
	require.NoError(t, err)
	for _, file := range files {
		contents, err := os.ReadFile(file)
		require.NoError(t, err)
		var control controlManifest
		require.NoError(t, json.Unmarshal(contents, &control))
		if control.ControlID == controlID {
			return control
		}
	}
	t.Fatalf("control %q is not present in controls", controlID)
	return controlManifest{}
}

func readAgentRuntimeRule(t *testing.T, ruleName string) reporthandling.PolicyRule {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "rules", ruleName, "rule.metadata.json"))
	require.NoError(t, err)
	var rule reporthandling.PolicyRule
	require.NoError(t, json.Unmarshal(contents, &rule))
	require.Equal(t, ruleName, rule.Name)
	return rule
}

// These fixtures must also work after the production processor filters inputs by
// rule metadata; passing data.json straight to OPA misses missing declarations.
func TestAgentRuntimeConfiguredInputs(t *testing.T) {
	for _, name := range []string{
		"agent-sandbox-hardened-runtime-class", "agent-runtime-image-registries",
		"agent-sandbox-strict-egress", "worker-pod-resource-ceilings",
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "rules", name)
			metadata, err := os.ReadFile(filepath.Join(root, "rule.metadata.json"))
			require.NoError(t, err)
			var rule reporthandling.PolicyRule
			require.NoError(t, json.Unmarshal(metadata, &rule))
			module, err := os.ReadFile(filepath.Join(root, "raw.rego"))
			require.NoError(t, err)
			cases, err := filepath.Glob(filepath.Join(root, "test", "*"))
			require.NoError(t, err)
			for _, path := range cases {
				t.Run(filepath.Base(path), func(t *testing.T) {
					var deps resources.RegoDependenciesData
					raw, err := os.ReadFile(filepath.Join(path, "data.json"))
					if !os.IsNotExist(err) {
						require.NoError(t, err)
						require.NoError(t, json.Unmarshal(raw, &deps))
					}
					filtered := resources.RegoDependenciesData{
						PostureControlInputs: deps.GetFilteredPostureControlConfigInputs(rule.ControlConfigInputs),
					}
					store, err := filtered.TOStorage()
					require.NoError(t, err)
					files, err := filepath.Glob(filepath.Join(path, "input", "*.yaml"))
					require.NoError(t, err)
					var input []interface{}
					for _, file := range files {
						contents, err := os.ReadFile(file)
						require.NoError(t, err)
						var object map[string]interface{}
						require.NoError(t, yaml.Unmarshal(contents, &object))
						input = append(input, object)
					}
					result, err := rego.New(rego.Query("data.armo_builtins.deny"),
						rego.Module(name, string(module)), rego.Input(input), rego.Store(store)).Eval(context.Background())
					require.NoError(t, err)
					require.Len(t, result, 1)
					actual := result[0].Expressions[0].Value.([]interface{})
					expectedFile, err := os.ReadFile(filepath.Join(path, "expected.json"))
					require.NoError(t, err)
					var expected []map[string]interface{}
					require.NoError(t, json.Unmarshal(expectedFile, &expected))
					require.Len(t, actual, len(expected))
					var gotPaths, wantPaths []string
					for _, finding := range actual {
						for _, p := range finding.(map[string]interface{})["failedPaths"].([]interface{}) {
							gotPaths = append(gotPaths, p.(string))
						}
					}
					for _, finding := range expected {
						for _, p := range finding["failedPaths"].([]interface{}) {
							wantPaths = append(wantPaths, p.(string))
						}
					}
					sort.Strings(gotPaths)
					sort.Strings(wantPaths)
					require.Equal(t, wantPaths, gotPaths)
				})
			}
		})
	}
}

// The standard rule runner merges repository defaults, so test an older
// configuration with no runtime allowlist directly through the filtered input
// path. This distinguishes an absent input from a configured default.
func TestAgentRuntimeMissingInputs(t *testing.T) {
	for _, name := range []string{"agent-sandbox-hardened-runtime-class", "agent-runtime-image-registries"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "rules", name)
			module, err := os.ReadFile(filepath.Join(root, "raw.rego"))
			require.NoError(t, err)
			metadata, err := os.ReadFile(filepath.Join(root, "rule.metadata.json"))
			require.NoError(t, err)
			var rule reporthandling.PolicyRule
			require.NoError(t, json.Unmarshal(metadata, &rule))
			deps := resources.RegoDependenciesData{PostureControlInputs: map[string][]string{}}
			filtered := resources.RegoDependenciesData{PostureControlInputs: deps.GetFilteredPostureControlConfigInputs(rule.ControlConfigInputs)}
			store, err := filtered.TOStorage()
			require.NoError(t, err)
			for _, kind := range []string{"Sandbox", "SandboxTemplate"} {
				var input interface{}
				require.NoError(t, json.Unmarshal([]byte(`[{"kind":"`+kind+`","metadata":{"name":"missing-config"},"spec":{"podTemplate":{"spec":{"runtimeClassName":"runc","containers":[{"image":"evil.example/actor"}]}}}}]`), &input))
				result, err := rego.New(rego.Query("data.armo_builtins.deny"), rego.Module(name, string(module)), rego.Input(input), rego.Store(store)).Eval(context.Background())
				require.NoError(t, err)
				require.Len(t, result, 1)
				require.Empty(t, result[0].Expressions[0].Value)
			}
		})
	}
}

// File scans retain explicit nulls in optional resource fields. They must report
// missing limits just as they do when those fields are omitted.
func TestAgentRuntimeNullResourceSettings(t *testing.T) {
	deps := resources.RegoDependenciesData{PostureControlInputs: map[string][]string{
		"cpu_limit_max": {"1"}, "memory_limit_max": {"1Gi"},
	}}
	store, err := deps.TOStorage()
	require.NoError(t, err)
	for _, kind := range []string{"WorkerPool", "Sandbox", "SandboxTemplate"} {
		name := "agent-sandbox-container-limits"
		settings := []string{`{"resources":null}`, `{"resources":{"limits":null}}`}
		want := []string{"spec.podTemplate.spec.containers[0].resources.limits"}
		if kind == "WorkerPool" {
			name = "worker-pod-resource-ceilings"
			settings = append(settings, `null`)
			want = []string{"spec.template.resources.limits.cpu", "spec.template.resources.limits.memory"}
		}
		module, err := os.ReadFile(filepath.Join("..", "rules", name, "raw.rego"))
		require.NoError(t, err)
		for _, setting := range settings {
			t.Run(kind+"/"+setting, func(t *testing.T) {
				spec := `{"replicas":1,"workerImage":"worker","template":` + setting + `}`
				if kind != "WorkerPool" {
					spec = `{"podTemplate":{"spec":{"containers":[{"name":"agent","image":"agent",` + setting[1:] + `]}}}`
				}
				var input interface{}
				require.NoError(t, json.Unmarshal([]byte(`[{"kind":"`+kind+`","metadata":{"name":"null-resources"},"spec":`+spec+`}]`), &input))
				result, err := rego.New(rego.Query("data.armo_builtins.deny"), rego.Module(name, string(module)), rego.Input(input), rego.Store(store)).Eval(context.Background())
				require.NoError(t, err)
				require.Len(t, result, 1)
				var paths []string
				for _, finding := range result[0].Expressions[0].Value.([]interface{}) {
					for _, path := range finding.(map[string]interface{})["failedPaths"].([]interface{}) {
						paths = append(paths, path.(string))
					}
				}
				require.ElementsMatch(t, want, paths)
			})
		}
	}
}
