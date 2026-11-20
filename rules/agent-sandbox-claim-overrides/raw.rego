# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	wl.kind == "SandboxTemplate"
	field := ["envVarsInjectionPolicy", "volumeClaimTemplatesPolicy"][_]
	wl.spec[field] == "Overrides"
	path := concat("", ["spec.", field])
	msg := {"alertMessage": sprintf("SandboxTemplate %s permits claims to replace template values", [field]), "packagename": "armo_builtins", "failedPaths": [path], "reviewPaths": [path], "fixPaths": [], "alertScore": 8, "alertObject": {"k8sApiObjects": [wl]}}
}
