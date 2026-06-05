# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
    some obj in input
	is_api_server(obj)
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}

is_api_server(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
}
