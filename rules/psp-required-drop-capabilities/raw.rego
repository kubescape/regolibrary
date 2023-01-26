package armo_builtins

import future.keywords.every

deny[msga] {
	# only fail resources if all PSPs don't have requiredDropCapabilities
	# if even one PSP has requiredDropCapabilities, then the rule will not fail
	every psp in input {
		psp.kind == "PodSecurityPolicy"
		not has_requiredDropCapabilities(psp.spec)
	}

	# return al the PSPs that don't have requiredDropCapabilities
	psp := input[_]
	psp.kind == "PodSecurityPolicy"
	not has_requiredDropCapabilities(psp.spec)

	fixpath := {"path":"spec.requiredDropCapabilities[0]", "value":"ALL"}
	msga := {
		"alertMessage": sprintf("PodSecurityPolicy: '%v' doesn't have requiredDropCapabilities.", [psp.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [fixpath],
		"alertObject": {"k8sApiObjects": [psp]},
	}
}

has_requiredDropCapabilities(spec) {
	count(spec.requiredDropCapabilities) > 0
}
