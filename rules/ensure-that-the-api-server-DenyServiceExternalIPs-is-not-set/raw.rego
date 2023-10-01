package armo_builtins

import future.keywords.in

deny[msg] {
	obj = input[_]
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0].command)
	msg := {
		"alertMessage": "admission control plugin DenyServiceExternalIPs is enabled. This is equal to turning off all admission controllers",
		"alertScore": 2,
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_api_server(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
}

get_flag_values(cmd) = {"origin": origin, "values": values} {
	re := " ?--enable-admission-plugins=(.+?)(?: |$)"
	matchs := regex.find_all_string_submatch_n(re, cmd, -1)
	count(matchs) == 1
	values := [val | val := split(matchs[0][1], ",")[j]; val != ""]
	origin := matchs[0][0]
}

# Assume flag set only once
invalid_flag(cmd) = result {
	flag := get_flag_values(cmd[i])

	# value check
	"DenyServiceExternalIPs" in flag.values

	# get fixed and failed paths
	fixed_values := [val | val := flag.values[j]; val != "DenyServiceExternalIPs"]
	result = get_retsult(fixed_values, i)
}

get_retsult(fixed_values, i) = result {
	count(fixed_values) == 0
	result = {
		"failed_paths": [sprintf("spec.containers[0].command[%v]", [i])],
		"fix_paths": [],
	}
}

get_retsult(fixed_values, i) = result {
	count(fixed_values) > 0
	path = sprintf("spec.containers[0].command[%v]", [i])
	result = {
		"failed_paths": [path],
		"fix_paths": [{
			"path": path,
			"value": sprintf("--enable-admission-plugins=%v", [concat(",", fixed_values)]),
		}],
	}
}
