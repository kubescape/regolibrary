# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0])
	msg := {
		"alertMessage": "TLS certificate authority file is not specified",
		"alertScore": 2,
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
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

# Assume flag set only once
invalid_flag(container) := result if {
	cmd := get_flags(container)
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--kubelet-certificate-authority")
	result := {
		"failed_paths": [],
		"fix_paths": [{
			"path": append_path(container, 0),
			"value": "--kubelet-certificate-authority=<path/to/ca.crt>",
		}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-apiserver"] and pass all flags via args.
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

# Path at which to add the k-th missing flag. RKE2/k3s carry flags in args,
# kubeadm in command, so the fix must target whichever array the container uses.
append_path(container, k) := sprintf("spec.containers[0].args[%d]", [count([arg | arg := container.args[_]]) + k]) if {
	count([arg | arg := container.args[_]]) > 0
} else := sprintf("spec.containers[0].command[%d]", [count(container.command) + k])
