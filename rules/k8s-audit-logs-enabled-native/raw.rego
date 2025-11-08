package armo_builtins

import rego.v1

import data.cautils

# Check if audit logs is  enabled for native k8s
deny contains msga if {
	apiserverpod := input[_]
	cmd := apiserverpod.spec.containers[0].command
	audit_policy := [command | command := cmd[_]; contains(command, "--audit-policy-file=")]
	count(audit_policy) < 1
	path := "spec.containers[0].command"

	msga := {
		"alertMessage": "audit logs is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [apiserverpod]},
	}
}
