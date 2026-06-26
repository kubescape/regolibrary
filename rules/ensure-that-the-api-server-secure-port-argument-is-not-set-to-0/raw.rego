# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_api_server(obj)
	flags := get_flags(obj.spec.containers[0])
	contains(flags[i], "--secure-port=0")
	msg := {
		"alertMessage": "the secure port is disabled",
		"alertScore": 2,
		"reviewPaths": [sprintf("spec.containers[0].command[%v]", [i])],
		"failedPaths": [sprintf("spec.containers[0].command[%v]", [i])],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_api_server(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-apiserver"] and pass all flags via args.
get_flags(container) := array.concat(container.command, object.get(container, "args", []))
