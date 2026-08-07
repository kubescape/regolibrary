# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	pod_spec := object.get(object.get(wl.spec, "podTemplate", {}), "spec", {})
	not object.get(pod_spec, "automountServiceAccountToken", true) == false
	msg := agent_token_message(wl)
}

agent_token_message(wl) := {"alertMessage": sprintf("%v must explicitly disable service account token automounting", [wl.kind]), "packagename": "armo_builtins", "failedPaths": ["spec.podTemplate.spec.automountServiceAccountToken"], "fixPaths": [{"path": "spec.podTemplate.spec.automountServiceAccountToken", "value": "false"}], "alertScore": 8, "alertObject": {"k8sApiObjects": [wl]}}
