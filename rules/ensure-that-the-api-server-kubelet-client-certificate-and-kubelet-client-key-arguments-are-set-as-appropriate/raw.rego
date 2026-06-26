# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_api_server(obj)
	result = invalid_flag(get_flags(obj.spec.containers[0]))
	msg := {
		"alertMessage": "certificate based kubelet authentication is not enabled",
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
invalid_flag(cmd) := result if {
	full_cmd = concat(" ", cmd)
	wanted = [
		"--kubelet-client-certificate",
		"--kubelet-client-key",
	]

	fix_paths = [{
		"path": sprintf("spec.containers[0].command[%d]", [count(cmd) + i]),
		"value": sprintf("%s=<path/to/appropriate/file>", [wanted[i]]),
	} |
		wanted[i]
		not contains(full_cmd, wanted[i])
	]

	count(fix_paths) > 0

	result = {
		"failed_paths": [],
		"fix_paths": fix_paths,
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-apiserver"] and pass all flags via args.
get_flags(container) := array.concat(container.command, object.get(container, "args", []))
