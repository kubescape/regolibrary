package armo_builtins


# Check if encryption in etcd in enabled for native k8s
deny[msga] {
	apiserverpod := input[_]
    cmd := apiserverpod.spec.containers[0].command[j]
    contains(cmd, "--encryption-provider-config=")
	path := sprintf("spec.containers[0].command[%v]", [format_int(j, 10)])
	
	msga := {
		"alertMessage": sprintf("etcd encryption is not enabled"),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": 
		}
	}
}