package armo_builtins


# Check if psp is enabled for native k8s
deny[msga] {
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
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [apiserverpod],
		
		}
	}
}