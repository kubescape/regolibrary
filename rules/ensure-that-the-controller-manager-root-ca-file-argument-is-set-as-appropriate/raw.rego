package armo_builtins

import future.keywords.in

deny[msg] {
	obj = input[_]
	is_controller_manager(obj)
	result = invalid_flag(obj.spec.containers[0].command)
	msg := {
		"alertMessage": "the controller manager is not configured to inject the trusted ca.crt file into pods so that they can verify TLS connections to the API server",
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
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--root-ca-file")
	result := {
		"failed_paths": [],
		"fix_paths": [{
			"path": sprintf("spec.containers[0].command[%d]", [count(cmd)]),
			"value": "--root-ca-file=<path/to/key/ca.crt>",
		}],
	}
}
