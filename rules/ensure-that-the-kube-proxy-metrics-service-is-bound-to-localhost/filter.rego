# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Filter to identify kube-proxy ConfigMap in kube-system namespace
deny contains msga if {
	configmap := input[_]
	configmap.kind == "ConfigMap"
	configmap.metadata.name == "kube-proxy"
	configmap.metadata.namespace == "kube-system"

	msga := {
		"alertMessage": "",
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [configmap]},
	}
}
