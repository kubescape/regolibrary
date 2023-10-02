package armo_builtins

import future.keywords.in

deny[msg] {
	obj = input[_]
	is_controller_manager(obj)
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

is_controller_manager(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-controller-manager")
}

# Assume flag set only once
invalid_flag(cmd) = result {
	contains(cmd[i], "--terminated-pod-gc-threshold")
	result = {
		"alert": "Please validate that --terminated-pod-gc-threshold is set to an appropriate value",
		"failed_paths": [sprintf("spec.containers[0].command[%v]", [i])],
		"fix_paths": [],
	}
}

invalid_flag(cmd) = result {
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--terminated-pod-gc-threshold")
	path = sprintf("spec.containers[0].command[%v]", [count(cmd)])
	result = {
		"alert": "--terminated-pod-gc-threshold flag not set to an appropriate value",
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": "--terminated-pod-gc-threshold=YOUR_VALUE"}],
	}
}
