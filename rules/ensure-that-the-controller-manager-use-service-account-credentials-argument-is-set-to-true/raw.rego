# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_controller_manager(obj)
	result = invalid_flag(obj.spec.containers[0])
	msg := {
		"alertMessage": "--use-service-account-credentials is set to false in the controller manager",
		"alertScore": 2,
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_controller_manager(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-controller-manager")
}

# Assume flag set only once
invalid_flag(container) := result if {
	cmd := get_flags(container)
	cmd[i] == "--use-service-account-credentials=false"
	path := flag_path(container, i)
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": "--use-service-account-credentials=true"}],
	}
}

invalid_flag(container) := result if {
	cmd := get_flags(container)
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--use-service-account-credentials")
	path := append_path(container, 0)
	result = {
		"failed_paths": [],
		"fix_paths": [{
			"path": path,
			"value": "--use-service-account-credentials=true",
		}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-controller-manager"] and pass all flags via args.
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

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
