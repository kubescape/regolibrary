# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Check if tls is configured in a etcd service
deny contains msga if {
	some obj in input
	is_etcd_pod(obj)

	result = invalid_flag(obj.spec.containers[0])

	msga := {
		"alertMessage": "etcd encryption is not enabled",
		"alertScore": 8,
		"packagename": "armo_builtins",
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_etcd_pod(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	count(obj.spec.containers) == 1
	endswith(split(obj.spec.containers[0].command[0], " ")[0], "etcd")
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["etcd"] and pass all flags via args.
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

# Assume flag set only once
invalid_flag(container) := result if {
	cmd := get_flags(container)
	full_cmd = concat(" ", cmd)
	wanted = [
		["--cert-file", "<path/to/tls-certificate-file.crt>"],
		["--key-file", "<path/to/tls-key-file.key>"],
	]

	fix_paths = [{
		"path": append_path(container, i),
		"value": sprintf("%s=%s", wanted[i]),
	} |
		not contains(full_cmd, wanted[i][0])
	]

	count(fix_paths) > 0

	result = {
		"failed_paths": [],
		"fix_paths": fix_paths,
	}
}

# Path at which to add the k-th missing flag. RKE2/k3s carry flags in args,
# kubeadm in command, so the fix must target whichever array the container uses.
append_path(container, k) := sprintf("spec.containers[0].args[%d]", [count([arg | arg := container.args[_]]) + k]) if {
	count([arg | arg := container.args[_]]) > 0
} else := sprintf("spec.containers[0].command[%d]", [count(container.command) + k])
