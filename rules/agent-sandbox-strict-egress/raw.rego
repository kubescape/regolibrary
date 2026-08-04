# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	"strict" in object.get(data.postureControlInputs, "agentSandboxEgressMode", ["managed"])
	not agent_sandbox_has_strict_egress(wl)
	msg := {"alertMessage": "Strict mode requires an explicit managed default-deny egress policy; the managed default still permits public internet", "packagename": "armo_builtins", "failedPaths": ["spec.networkPolicy"], "fixPaths": [], "alertScore": 8, "alertObject": {"k8sApiObjects": [wl]}}
}

agent_sandbox_has_strict_egress(wl) if {
	object.get(wl.spec, "networkPolicyManagement", "Managed") == "Managed"
	policy := wl.spec.networkPolicy
	count(object.get(policy, "egress", [])) == 0
}
