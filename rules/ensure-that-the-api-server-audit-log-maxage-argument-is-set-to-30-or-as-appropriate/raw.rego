package armo_builtins

import future.keywords.in

deny[msg] {
	obj = input[_]
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0].command)
	msg := {
		"alertMessage": result.alert,
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

get_flag_value(cmd) = {"origin": origin, "value": value} {
	re := " ?--audit-log-maxage=(.+?)(?: |$)"
	matchs := regex.find_all_string_submatch_n(re, cmd, -1)
	count(matchs) == 1
	value = to_number(matchs[0][1])
	origin := matchs[0][0]
}

# Assume flag set only once
invalid_flag(cmd) = result {
	flag = get_flag_value(cmd[i])
	flag.value < 30
	fixed = replace(cmd[i], flag.origin, "--audit-log-maxage=30")
	path = sprintf("spec.containers[0].command[%v]", [i])
	result = {
		"alert": sprintf("Audit log retention period is %v days, which is too small (should be at least 30 days)", [flag.value]),
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": fixed}],
	}
}

invalid_flag(cmd) = result {
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--audit-log-maxage")
	result = {
		"alert": "Audit log retention period is not set",
		"failed_paths": [],
		"fix_paths": [{
			"path": sprintf("spec.containers[0].command[%v]", [count(cmd)]),
			"value": "--audit-log-maxage=30",
		}],
	}
}
