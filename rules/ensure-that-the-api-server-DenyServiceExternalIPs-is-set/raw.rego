# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0])
	msg := {
		"alertMessage": "admission control plugin DenyServiceExternalIPs is not enabled.",
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

get_flag_values(cmd) := {"origin": origin, "values": values} if {
	re := " ?--enable-admission-plugins=(.+?)(?: |$)"
	matchs := regex.find_all_string_submatch_n(re, cmd, -1)
	count(matchs) == 1
	values := [val | val := split(matchs[0][1], ",")[j]; val != ""]
	origin := matchs[0][0]
}

# Assume flag set only once
invalid_flag(container) := result if {
	cmd := get_flags(container)
	flag := get_flag_values(cmd[i])

	# value check
	not "DenyServiceExternalIPs" in flag.values

	# get fixed and failed paths
	result = get_retsult(container, i)
}

get_retsult(container, i) := result if {
	path = flag_path(container, i)
	result = {
		"failed_paths": [path],
		"fix_paths": [{
			"path": path,
			"value": sprintf("--enable-admission-plugins=%v", ["DenyServiceExternalIPs"]),
		}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-apiserver"] and pass all flags via args.
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

# Map an index into the combined command+args list back to the real path, so
# findings on RKE2/k3s point at args[j] instead of a non-existent command[i].
flag_path(container, i) := sprintf("spec.containers[0].command[%d]", [i]) if {
	i < count(container.command)
} else := sprintf("spec.containers[0].args[%d]", [i - count(container.command)])
