package armo_builtins

import rego.v1

deny contains msga if {
	# only fail resources if there all PSPs have allowPrivilegeEscalation set to true
	# if even one PSP has allowPrivilegeEscalation set to false, then the rule will not fail
	every psp in input {
		psp.kind == "PodSecurityPolicy"
		psp.spec.allowPrivilegeEscalation == true
	}

	# return al the PSPs that have allowPrivilegeEscalation set to true
	psp := input[_]
	psp.kind == "PodSecurityPolicy"
	psp.spec.allowPrivilegeEscalation == true

	path := "spec.allowPrivilegeEscalation"
	msga := {
		"alertMessage": sprintf("PodSecurityPolicy: '%v' has allowPrivilegeEscalation set as true.", [psp.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [psp]},
	}
}
