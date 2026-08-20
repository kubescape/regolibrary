# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Check if --client-cert-auth is set to true
deny contains msga if {
	some obj in input
	is_etcd_pod(obj)
	result = invalid_flag(obj.spec.containers[0])

	msga := {
		"alertMessage": "Etcd server is not requiring a valid client certificate",
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
	not contains(full_cmd, "--client-cert-auth")
	result := {
		"failed_paths": [],
		"fix_paths": [{
			"path": append_path(container, 0),
			"value": "--client-cert-auth=true",
		}],
	}
}

invalid_flag(container) := result if {
	cmd := get_flags(container)
	contains(cmd[i], "--client-cert-auth=false")
	fixed = replace(cmd[i], "--client-cert-auth=false", "--client-cert-auth=true")
	path := flag_path(container, i)
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": fixed}],
	}
}

# Map an index into the combined command+args list back to the real path, so
# findings on RKE2/k3s point at args[j] instead of a non-existent command[i].
flag_path(container, i) := sprintf("spec.containers[0].command[%d]", [i]) if {
	i < count(container.command)
} else := sprintf("spec.containers[0].args[%d]", [i - count(container.command)])

# Path at which to add the k-th missing flag. RKE2/k3s carry flags in args,
# kubeadm in command, so the fix must target whichever array the container uses.
append_path(container, k) := sprintf("spec.containers[0].args[%d]", [count([arg | arg := container.args[_]]) + k]) if {
	count([arg | arg := container.args[_]]) > 0
} else := sprintf("spec.containers[0].command[%d]", [count(container.command) + k])
