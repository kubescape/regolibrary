# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	allowed := object.get(data.postureControlInputs, "agentRuntimeClassAllowList", [])
	count(allowed) > 0
	runtime_class := object.get(object.get(object.get(wl.spec, "podTemplate", {}), "spec", {}), "runtimeClassName", "")
	not runtime_class in allowed
	msg := agent_runtime_message(wl, "spec.podTemplate.spec.runtimeClassName", sprintf("%v must select an approved sandbox RuntimeClass", [wl.kind]), 9)
}

agent_runtime_message(wl, path, message, score) := {"alertMessage": message, "packagename": "armo_builtins", "failedPaths": [path], "fixPaths": [], "alertScore": score, "alertObject": {"k8sApiObjects": [wl]}}
