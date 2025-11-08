package armo_builtins

import rego.v1

deny contains msg if {
	obj = input[_]
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0].command)
	msg := {
		"alertMessage": "API server is not configured to use SSL Certificate Authority file for etcd",
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
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--etcd-cafile")
	result := {
		"failed_paths": [],
		"fix_paths": [{
			"path": sprintf("spec.containers[0].command[%d]", [count(cmd)]),
			"value": "--etcd-cafile=<path/to/ca-file.crt>",
		}],
	}
}
