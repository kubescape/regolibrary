# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_controller_manager(obj)
	result = invalid_flag(obj.spec.containers[0])
	msg := {
		"alertMessage": "profiling is enabled for the kube-controller-manager",
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

# A repeated flag takes its value from the last occurrence in command + args,
# the same way pflag parses it.
last_flag_index(flags) := max({i |
	some i, arg in flags
	split(arg, "=")[0] == "--profiling"
})

invalid_flag(container) := result if {
	flags := get_flags(container)
	i := last_flag_index(flags)

	# A bare boolean flag means true, and pflag accepts every true spelling of strconv.ParseBool.
	suffix := trim_prefix(flags[i], "--profiling")
	suffix in {"", "=1", "=t", "=T", "=true", "=TRUE", "=True"}
	path := flag_path(container, i)
	result := {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": "--profiling=false"}],
	}
}

# Profiling is enabled by default, so a missing flag fails too.
invalid_flag(container) := result if {
	not last_flag_index(get_flags(container))
	path := append_path(container, 0)
	result := {
		"failed_paths": [],
		"fix_paths": [{
			"path": path,
			"value": "--profiling=false",
		}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-controller-manager"] and pass all flags via args. The
# comprehension over args is null-safe (an explicit `args: null` yields [] rather
# than erroring).
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
