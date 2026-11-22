# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	"strict" in object.get(data.postureControlInputs, "agentSandboxEgressMode", ["managed"])
	wl := input[_]
	wl.kind == "SandboxTemplate"
	not agent_sandbox_has_strict_egress(wl)
	msg := {"alertMessage": "Strict mode requires an explicit managed default-deny egress policy; the managed default still permits public internet", "packagename": "armo_builtins", "failedPaths": ["spec.networkPolicy"], "reviewPaths": strict_egress_review_paths(wl), "fixPaths": strict_egress_fix_paths(wl), "alertScore": 8, "alertObject": {"k8sApiObjects": [wl]}}
}

agent_sandbox_has_strict_egress(wl) if {
	management := object.get(wl, ["spec", "networkPolicyManagement"], null)
	management in {null, "Managed"}
	policy := object.get(wl, ["spec", "networkPolicy"], null)
	is_object(policy)
	egress := object.get(policy, "egress", null)
	is_array(egress)
	count(egress) == 0
}

# spec.networkPolicy when it is there, even as null, otherwise spec, so the
# evidence points at a field that is there.
strict_egress_review_paths(wl) := ["spec.networkPolicy"] if {
	has_network_policy(wl)
} else := ["spec"]

# An omitted policy is added as a managed default-deny one: an empty egress
# list. Only while the policy is managed: an Unmanaged template still fails
# with one, so there is no fix to propose.
strict_egress_fix_paths(wl) := [{"path": "spec.networkPolicy.egress", "value": "[]"}] if {
	not has_network_policy(wl)
	object.get(wl, ["spec", "networkPolicyManagement"], null) in {null, "Managed"}
} else := []

has_network_policy(wl) if {
	_ = wl.spec.networkPolicy
}
