# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	path := "spec.hostPID"
	# only fail resources if there all PSPs have hostPID set to true
	# if even one PSP has hostPID set to false, then the rule will not fail
	every psp in input {
		psp.kind == "PodSecurityPolicy"
		psp.spec.hostPID == true
	}

	# return al the PSPs that have hostPID set to true
	psp := input[_]
	psp.kind == "PodSecurityPolicy"
	psp.spec.hostPID == true

	msga := {
		"alertMessage": sprintf("PodSecurityPolicy: '%v' has hostPID set as true.", [psp.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [psp]},
	}
}
