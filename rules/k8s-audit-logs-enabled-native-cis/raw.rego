package armo_builtins

# CIS 3.2.1 https://workbench.cisecurity.org/sections/1126657/recommendations/1838582
deny[msga] {
	obj := input[_]
	is_api_server(obj)
	cmd := obj.spec.containers[0].command
	audit_policy := [command | command := cmd[_]; contains(command, "--audit-policy-file=")]
	count(audit_policy) < 1
	path := sprintf("spec.containers[0].command[%v]", [count(cmd)])

	msga := {
		"alertMessage": "audit logs are not enabled",
		"alertScore": 5,
		"packagename": "armo_builtins",
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
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
