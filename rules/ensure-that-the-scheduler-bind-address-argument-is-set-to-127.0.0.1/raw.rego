# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_scheduler(obj)
	result = invalid_flag(obj.spec.containers[0])

	msg := {
		"alertMessage": "the kube scheduler is not bound to a localhost interface only",
		"alertScore": 2,
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_scheduler(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-scheduler")
}

get_flag_value(cmd) := value if {
	re := " ?--bind-address=(.+?)(?: |$)"
	matchs := regex.find_all_string_submatch_n(re, cmd, 1)
	count(matchs) == 1
	value = matchs[0][1]
}

# Assume flag set only once
invalid_flag(container) := result if {
	cmd := get_flags(container)
	val = get_flag_value(cmd[i])
	val != "127.0.0.1"
	path = flag_path(container, i)
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": "--bind-address=127.0.0.1"}],
	}
}

invalid_flag(container) := result if {
	cmd := get_flags(container)
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--bind-address")
	path = append_path(container, 0)
	result = {
		"failed_paths": [],
		"fix_paths": [{"path": path, "value": "--bind-address=127.0.0.1"}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-scheduler"] and pass all flags via args.
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
