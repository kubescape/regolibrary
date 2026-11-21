# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	"strict" in object.get(data.postureControlInputs, "agentSandboxEgressMode", ["managed"])
	wl := input[_]
	wl.kind == "SandboxTemplate"
	not agent_sandbox_has_strict_egress(wl)
	msg := {"alertMessage": "Strict mode requires an explicit managed default-deny egress policy; the managed default still permits public internet", "packagename": "armo_builtins", "failedPaths": ["spec.networkPolicy"], "reviewPaths": ["spec.networkPolicy"], "fixPaths": [], "alertScore": 8, "alertObject": {"k8sApiObjects": [wl]}}
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
