package armo_builtins

import rego.v1

import data.cautils

# Check if encryption in etcd is enabled for native k8s
deny contains msga if {
	apiserverpod := input[_]
	cmd := apiserverpod.spec.containers[0].command
	enc_command := [command | command := cmd[_]; contains(command, "--encryption-provider-config=")]
	count(enc_command) < 1
	fixpath := {"path": sprintf("spec.containers[0].command[%d]", [count(cmd)]), "value": "--encryption-provider-config=YOUR_VALUE"}

	msga := {
		"alertMessage": "etcd encryption is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [fixpath],
		"alertObject": {"k8sApiObjects": [apiserverpod]},
	}
}
