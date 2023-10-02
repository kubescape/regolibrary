package armo_builtins

import future.keywords.in



deny[msg] {
	obj = input[_]
	is_controller_manager(obj)
	result = invalid_flag(obj.spec.containers[0].command)

	msg := {
		"alertMessage": "the Controller Manager API service is not bound to a localhost interface only",
		"alertScore": 2,
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_controller_manager(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-controller-manager")
}

get_flag_value(cmd) = value {
	re := " ?--bind-address=(.+?)(?: |$)"
	matchs := regex.find_all_string_submatch_n(re, cmd, 1)
	count(matchs) == 1
	value =matchs[0][1]
}

# Assume flag set only once
invalid_flag(cmd) = result {
	val = get_flag_value(cmd[i])
	val != "127.0.0.1"
	path = sprintf("spec.containers[0].command[%d]", [i])
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": "--bind-address=127.0.0.1"}],
	}
}

invalid_flag(cmd) = result {
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--bind-address")
	path = sprintf("spec.containers[0].command[%d]", [count(cmd)])
	result = {
		"failed_paths": [],
		"fix_paths": [{"path": path, "value": "--bind-address=127.0.0.1"}],
	}
}