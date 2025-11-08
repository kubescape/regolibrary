package armo_builtins

import rego.v1

deny contains msg if {
	obj = input[_]
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0].command)
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
invalid_flag(cmd) := result if {
	flag := get_flag_values(cmd[i])

	# value check
	not "DenyServiceExternalIPs" in flag.values

	# get fixed and failed paths
	result = get_retsult(i)
}

get_retsult(i) := result if {
	path = sprintf("spec.containers[0].command[%v]", [i])
	result = {
		"failed_paths": [path],
		"fix_paths": [{
			"path": path,
			"value": sprintf("--enable-admission-plugins=%v", ["DenyServiceExternalIPs"]),
		}],
	}
}
