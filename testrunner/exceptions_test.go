package testing

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const supervisorSyncedLabel = "run.tanzu.vmware.com/vmware-system-synced-from-supervisor"

// The vSphere Supervisor creates and re-syncs ClusterRoleBindings in every VKS guest cluster, for
// example binding the vCenter SSO group sso:Administrators@vsphere.local to cluster-admin. The
// customer cannot remove them, so exceptions/vmware-vks.json excepts them from the RBAC controls.
// The exception must apply only to Supervisor-synced bindings (name AND label), only to the RBAC
// controls it lists, and never to a customer's own binding of the same subject.
func TestVMwareVKSSystemException(t *testing.T) {
	raw, err := os.ReadFile("../exceptions/vmware-vks.json")
	require.NoError(t, err)
	var policies []armotypes.PostureExceptionPolicy
	require.NoError(t, json.Unmarshal(raw, &policies))

	clusterAdmin := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]interface{}{"name": "cluster-admin"},
		"rules": []interface{}{map[string]interface{}{
			"apiGroups": []interface{}{"*"}, "resources": []interface{}{"*"}, "verbs": []interface{}{"*"},
		}},
	}
	binding := func(name string, labels map[string]interface{}) map[string]interface{} {
		metadata := map[string]interface{}{"name": name}
		if labels != nil {
			metadata["labels"] = labels
		}
		return map[string]interface{}{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "ClusterRoleBinding",
			"metadata":   metadata,
			"roleRef":    map[string]interface{}{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
			"subjects": []interface{}{map[string]interface{}{
				"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "sso:Administrators@vsphere.local",
			}},
		}
	}
	// "yes" is the value the Supervisor sets on real VKS bindings; the exception accepts any value.
	synced := map[string]interface{}{supervisorSyncedLabel: "yes"}

	tests := []struct {
		name      string
		binding   map[string]interface{}
		controlID string
		excepted  bool
	}{
		{"supervisor-synced binding, C-0185", binding("vmware-system-auth-sync-wcp:shared:group:vsphere.local:administrators", synced), "C-0185", true},
		{"supervisor-synced binding, C-0188", binding("vmware-system-auth-sync-wcp:shared:group:vsphere.local:administrators", synced), "C-0188", true},
		{"supervisor-synced binding, C-0035", binding("vmware-system-auth-sync-wcp:shared:group:vsphere.local:administrators", synced), "C-0035", true},
		{"supervisor-synced binding, C-0187", binding("vmware-system-auth-sync-wcp:shared:group:vsphere.local:administrators", synced), "C-0187", true},
		{"any label value matches", binding("vmware-system-auth-sync-wcp:ns1:group:vsphere.local:administrators", map[string]interface{}{supervisorSyncedLabel: ""}), "C-0185", true},
		{"control not in scope", binding("vmware-system-auth-sync-wcp:shared:group:vsphere.local:administrators", synced), "C-0186", false},
		{"name matches, label missing", binding("vmware-system-auth-sync-wcp:shared:group:vsphere.local:administrators", nil), "C-0185", false},
		{"label present, other name", binding("my-vsphere-admins", synced), "C-0185", false},
		{"customer's own binding of the same group", binding("my-vsphere-admins", nil), "C-0185", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subjects, err := reporthandling.AggregateResourcesBySubjects([]workloadinterface.IMetadata{
				workloadinterface.NewWorkloadObj(tt.binding),
				workloadinterface.NewWorkloadObj(clusterAdmin),
			})
			require.NoError(t, err)
			require.Len(t, subjects, 1, "expected one subject vector for sso:Administrators@vsphere.local")

			processor := exceptions.NewProcessor()
			ruleExceptions := processor.ListRuleExceptions(policies, "", tt.controlID, "")
			got := processor.GetResourceExceptions(ruleExceptions, subjects[0], "any-cluster")
			assert.Equal(t, tt.excepted, len(got) > 0)
		})
	}
}
