package armo_builtins

import future.keywords.every

deny[msga] {
	# only fail resources if all PSPs permit containers to run as the root user
	# if even one PSP restricts containers to run as the root user, then the rule will not fail
	every psp in input {
		psp.kind == "PodSecurityPolicy"
		not deny_run_as_root(psp.spec.runAsUser)
	}

	# return al the PSPs that permit containers to run as the root user
	psp := input[_]
	psp.kind == "PodSecurityPolicy"
	not deny_run_as_root(psp.spec.runAsUser)

	path := "spec.runAsUser.rule"
	msga := {
		"alertMessage": sprintf("PodSecurityPolicy: '%v' permits containers to run as the root user.", [psp.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [psp]},
	}
}

deny_run_as_root(runAsUser){
	runAsUser.rule == "MustRunAsNonRoot"
}

deny_run_as_root(runAsUser){
	runAsUser.rule == "MustRunAs"
	runAsUser.ranges[_].min > 0
}