package armo_builtins

import rego.v1

deny contains msga if {
	# only fail resources if there all PSPs have hostIPC set to true
	# if even one PSP has hostIPC set to false, then the rule will not fail
	every psp in input {
		psp.kind == "PodSecurityPolicy"
		psp.spec.hostIPC == true
	}

	# return al the PSPs that have hostIPC set to true
	psp := input[_]
	psp.kind == "PodSecurityPolicy"
	psp.spec.hostIPC == true

	path := "spec.hostIPC"
	msga := {
		"alertMessage": sprintf("PodSecurityPolicy: '%v' has hostIPC set as true.", [psp.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [psp]},
	}
}
