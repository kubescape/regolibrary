# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Check if --auto-tls is not set to true
deny contains msga if {
	some obj in input
	is_etcd_pod(obj)

	result := invalid_flag(obj.spec.containers[0])

	msga := {
		"alertMessage": "Auto tls is enabled. Clients are able to use self-signed certificates for TLS.",
		"alertScore": 6,
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

invalid_flag(container) := result if {
	cmd := get_flags(container)
	contains(cmd[i], "--auto-tls=true")
	fixed = replace(cmd[i], "--auto-tls=true", "--auto-tls=false")
	path := flag_path(container, i)
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": fixed}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["etcd"] and pass all flags via args. The comprehension over args
# is null-safe (an explicit `args: null` yields [] rather than erroring).
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

# Map an index into the combined command+args list back to the real path, so
# findings on RKE2/k3s point at args[j] instead of a non-existent command[i].
flag_path(container, i) := sprintf("spec.containers[0].command[%d]", [i]) if {
	i < count(container.command)
} else := sprintf("spec.containers[0].args[%d]", [i - count(container.command)])
