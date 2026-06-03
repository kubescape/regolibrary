package armo_builtins

import rego.v1

deny contains msg if {
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
	contains(cmd[i], "--anonymous-auth=true")
	fixed = replace(cmd[i], "--anonymous-auth=true", "--anonymous-auth=false")
	path := sprintf("spec.containers[0].command[%d]", [i])
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": fixed}],
	}
}

invalid_flag(cmd) := result if {
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--anonymous-auth")
	path := sprintf("spec.containers[0].command[%d]", [count(cmd)])
	result = {
		"failed_paths": [],
		"fix_paths": [{
			"path": path,
			"value": "--anonymous-auth=false",
		}],
	}
}
