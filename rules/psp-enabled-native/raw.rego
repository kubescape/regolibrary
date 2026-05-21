package armo_builtins

import rego.v1

# Check if psp is enabled for native k8s
deny contains msga if {
	apiserverpod := input[_]
	cmd := apiserverpod.spec.containers[0].command[j]
	contains(cmd, "--enable-admission-plugins=")
	output := split(cmd, "=")
	not contains(output[1], "PodSecurityPolicy")
	path := sprintf("spec.containers[0].command[%v]", [format_int(j, 10)])

	msga := {
		"alertMessage": "PodSecurityPolicy is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [apiserverpod]},
	}
}
