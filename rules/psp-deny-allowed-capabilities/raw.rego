package armo_builtins

import future.keywords.every

deny[msga] {
	# only fail resources if all PSPs have allowedCapabilities
	# if even one PSP has allowedCapabilities as an empty list, then the rule will not fail
	every psp in input {
		psp.kind == "PodSecurityPolicy"
		count(psp.spec.allowedCapabilities) > 0
	}

	# return al the PSPs that have allowedCapabilities
	psp := input[_]
	psp.kind == "PodSecurityPolicy"
	count(psp.spec.allowedCapabilities) > 0

	path := "spec.allowedCapabilities"
	msga := {
		"alertMessage": sprintf("PodSecurityPolicy: '%v' has allowedCapabilities.", [psp.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [psp]},
	}
}
