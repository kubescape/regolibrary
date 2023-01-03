package armo_builtins

# return al the PSPs that have privileged set to true
deny[msga] {
    psp := input[_]
    psp.kind == "PodSecurityPolicy"
    psp.spec.privileged == true
    
	path := "spec.privileged"
    msga := {
		"alertMessage": sprintf("PodSecurityPolicy: '%v' has privileged set as true.", [psp.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
        "fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [psp]
		}
	}
}