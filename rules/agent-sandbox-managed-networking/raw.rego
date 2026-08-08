# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	object.get(wl.spec, "networkPolicyManagement", "Managed") != "Managed"
	msg := {"alertMessage": "SandboxTemplate explicitly disables managed networking", "packagename": "armo_builtins", "failedPaths": ["spec.networkPolicyManagement"], "fixPaths": [{"path": "spec.networkPolicyManagement", "value": "Managed"}], "alertScore": 7, "alertObject": {"k8sApiObjects": [wl]}}
}
