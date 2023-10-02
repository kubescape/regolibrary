package armo_builtins

import future.keywords.in

deny[msg] {
	obj = input[_]
	is_api_server(obj)
	contains(obj.spec.containers[0].command[i], "--secure-port=0")
	msg := {
		"alertMessage": "the secure port is disabled",
		"alertScore": 2,
		"reviewPaths": [sprintf("spec.containers[0].command[%v]", [i])],
		"failedPaths": [sprintf("spec.containers[0].command[%v]", [i])],
		"fixPaths": [],
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
