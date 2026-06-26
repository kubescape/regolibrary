# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_api_server(obj)
	result = invalid_flag(get_flags(obj.spec.containers[0]))
	msg := {
		"alertMessage": "API server TLS is not configured",
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
	re := " ?--token-auth-file=(.+?)(?: |$)"
	matchs := regex.find_all_string_submatch_n(re, cmd[i], -1)
	count(matchs) > 0
	fixed = replace(cmd[i], matchs[0][0], "")
	result = get_result(sprintf("spec.containers[0].command[%d]", [i]), fixed)
}

# Get fix and failed paths
get_result(path, fixed) := result if {
	fixed == ""
	result = {
		"failed_paths": [path],
		"fix_paths": [],
	}
}

get_result(path, fixed) := result if {
	fixed != ""
	result = {
		"failed_paths": [path],
		"fix_paths": [{
			"path": path,
			"value": fixed,
		}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-apiserver"] and pass all flags via args.
get_flags(container) := array.concat(container.command, object.get(container, "args", []))
