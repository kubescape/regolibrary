package armo_builtins

import future.keywords.every

deny[msga] {
	# only fail resources if there all PSPs have hostNetwork set to true
	# if even one PSP has hostNetwork set to false, then the rule will not fail
	every psp in input {
		psp.kind == "PodSecurityPolicy"
		psp.spec.hostNetwork == true
	}

	# return al the PSPs that have hostNetwork set to true
	psp := input[_]
	psp.kind == "PodSecurityPolicy"
	psp.spec.hostNetwork == true

	path := "spec.hostNetwork"
	msga := {
		"alertMessage": sprintf("PodSecurityPolicy: '%v' has hostNetwork set as true.", [psp.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [psp]},
	}
}
