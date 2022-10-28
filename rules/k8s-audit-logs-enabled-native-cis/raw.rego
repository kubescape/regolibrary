package armo_builtins

# CIS 3.2.1 https://workbench.cisecurity.org/sections/1126657/recommendations/1838582
deny[msga] {
	apiserverpod := input[_]
	cmd := apiserverpod.spec.containers[0].command
	audit_policy := [command | command := cmd[_]; contains(command, "--audit-policy-file=")]
	count(audit_policy) < 1
	path := sprintf("spec.containers[0].command[%v]", [count(cmd)])

	msga := {
		"alertMessage": "audit logs are not enabled",
		"alertScore": 5,
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [apiserverpod]},
	}
}
