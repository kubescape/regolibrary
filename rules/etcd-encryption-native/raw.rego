package armo_builtins

import data.cautils as cautils

# Check if encryption in etcd is enabled for native k8s
deny[msga] {
	apiserverpod := input[_]
	cmd := apiserverpod.spec.containers[0].command
	enc_command := [command | command := cmd[_]; contains(command, "--encryption-provider-config=")]
	count(enc_command) < 1
	path := "spec.containers[0].command"

	msga := {
		"alertMessage": "etcd encryption is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [apiserverpod]},
	}
}
