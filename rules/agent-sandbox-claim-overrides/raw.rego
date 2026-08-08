# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	field := ["envVarsInjectionPolicy", "volumeClaimTemplatesPolicy"][_]
	object.get(wl.spec, field, "Disallowed") == "Overrides"
	path := concat("", ["spec.", field])
	msg := {"alertMessage": sprintf("SandboxTemplate %s permits claims to replace template values", [field]), "packagename": "armo_builtins", "failedPaths": [path], "fixPaths": [], "alertScore": 8, "alertObject": {"k8sApiObjects": [wl]}}
}
