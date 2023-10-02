package armo_builtins

import future.keywords.in

deny[msg] {
	obj = input[_]
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0].command)
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

is_api_server(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
}

# Assume flag set only once
invalid_flag(cmd) := invalid_flags[0] {
	invalid_flags := [flag |
		some i, c in cmd
		flag := get_result(c, i)
	]
}

get_result(cmd, i) = result {
	cmd == "--service-account-lookup=false"
	result = {
		"failed_paths": [sprintf("spec.containers[0].command[%v]", [i])],
		"fix_paths": [],
	}
}

get_result(cmd, i) = result {
	cmd != "--service-account-lookup=false"
	contains(cmd, "--service-account-lookup=false")
	path = sprintf("spec.containers[0].command[%v]", [i])
	result = {
		"failed_paths": [path],
		"fix_paths": [{
			"path": path,
			"value": replace(cmd, "--service-account-lookup=false", "--service-account-lookup=true"),
		}],
	}
}
