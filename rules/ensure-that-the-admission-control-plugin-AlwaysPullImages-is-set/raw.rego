package armo_builtins

import future.keywords.in

deny[msg] {
	obj = input[_]
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0].command)
	msg := {
		"alertMessage": "Admission control policy is not set to AlwaysPullImages",
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
	not "AlwaysPullImages" in flag.values

	# get fixed and failed paths
	fixed_values := array.concat(flag.values, ["AlwaysPullImages"])
	fixed_flag = sprintf("%s=%s", ["--enable-admission-plugins", concat(",", fixed_values)])
	fixed_cmd = replace(cmd[i], flag.origin, fixed_flag)
	path := sprintf("spec.containers[0].command[%d]", [i])

	result := {
		"failed_paths": [path],
		"fix_paths": [{
			"path": path,
			"value": fixed_cmd,
		}],
	}
}

invalid_flag(cmd) = result {
	full_cmd := concat(" ", cmd)
	not contains(full_cmd, "--enable-admission-plugins")

	path = sprintf("spec.containers[0].command[%d]", [count(cmd)])
	result = {
		"failed_paths": [],
		"fix_paths": [{
			"path": path,
			"value": "--enable-admission-plugins=AlwaysPullImages",
		}],
	}
}
