package armo_builtins

import future.keywords.in

deny[msg] {
	obj = input[_]
	is_scheduler(obj)
	result = invalid_flag(obj.spec.containers[0].command)
	msg := {
		"alertMessage": "profiling is enabled for the kube-scheduler",
		"alertScore": 2,
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_scheduler(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-scheduler")
}

# Assume flag set only once
invalid_flag(cmd) = result {
	cmd[i] == "--profiling=true"
	path := sprintf("spec.containers[0].command[%d]", [i])
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": "--profiling=false"}],
	}
}

invalid_flag(cmd) = result {
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--profiling")
	path := sprintf("spec.containers[0].command[%d]", [count(cmd)])
	result = {
		"failed_paths": [],
		"fix_paths": [{
			"path": path,
			"value": "--profiling=false",
		}],
	}
}
