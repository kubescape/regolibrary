# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0])
	msg := {
		"alertMessage": "anonymous requests is enabled",
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
invalid_flag(container) := invalid_flags[0] if {
	cmd := get_flags(container)
	invalid_flags := [flag |
		some i, c in cmd
		flag := get_result(container, c, i)
	]
}

get_result(container, cmd, i) := result if {
	cmd == "--service-account-lookup=false"
	result = {
		"failed_paths": [flag_path(container, i)],
		"fix_paths": [],
	}
}

get_result(container, cmd, i) := result if {
	cmd != "--service-account-lookup=false"
	contains(cmd, "--service-account-lookup=false")
	path = flag_path(container, i)
	result = {
		"failed_paths": [path],
		"fix_paths": [{
			"path": path,
			"value": replace(cmd, "--service-account-lookup=false", "--service-account-lookup=true"),
		}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-apiserver"] and pass all flags via args. The comprehension
# over args is null-safe (an explicit `args: null` yields [] rather than erroring).
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

# Map an index into the combined command+args list back to the real path, so
# findings on RKE2/k3s point at args[j] instead of a non-existent command[i].
flag_path(container, i) := sprintf("spec.containers[0].command[%d]", [i]) if {
	i < count(container.command)
} else := sprintf("spec.containers[0].args[%d]", [i - count(container.command)])
