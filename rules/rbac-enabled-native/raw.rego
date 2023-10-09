package armo_builtins


# Check if psp is enabled for native k8s
deny[msga] {
	apiserverpod := input[_]
    cmd := apiserverpod.spec.containers[0].command[j]
    contains(cmd, "--authorization-mode=")
    output := split(cmd, "=")
    not contains(output[1], "RBAC")
	path := sprintf("spec.containers[0].command[%v]", [format_int(j, 10)])	
	
	msga := {
		"alertMessage": "RBAC is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [apiserverpod],
		}
	}
}