# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	container := object.get(wl.spec, "containers", [])[i]
	env := object.get(container, "env", [])[j]
	object.get(object.get(env, "valueFrom", {}), "secretKeyRef", null) != null
	path := sprintf("spec.containers[%d].env[%d].valueFrom.secretKeyRef", [i, j])
	msg := {"alertMessage": sprintf("ActorTemplate container %q references a Secret that can be captured in the golden snapshot", [container.name]), "packagename": "armo_builtins", "failedPaths": [path], "fixPaths": [], "alertScore": 9, "alertObject": {"k8sApiObjects": [wl]}}
}
