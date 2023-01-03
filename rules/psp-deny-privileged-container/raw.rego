package armo_builtins

import future.keywords.every

deny[msga] {
	# only fail resources if there all PSPs have privileged set to true
	# if even one PSP has privileged set to false, then the rule will not fail
	every psp in input {
		psp.kind == "PodSecurityPolicy"
		psp.spec.privileged == true
	}

	# return al the PSPs that have privileged set to true
	psp := input[_]
	psp.kind == "PodSecurityPolicy"
	psp.spec.privileged == true

	path := "spec.privileged"
	msga := {
		"alertMessage": sprintf("PodSecurityPolicy: '%v' has privileged set as true.", [psp.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [psp]},
	}
}
