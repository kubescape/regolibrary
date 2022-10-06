package armo_builtins


# Fails if pod does not define seccompProfile as RuntimeDefault
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    spec := pod.spec
	seccompProfile_not_defined_well(spec)
    container := pod.spec.containers[i]
    seccompProfile_not_defined_well(container)

	fixPaths := [{"path": sprintf("spec.containers[%v].securityContext.seccompProfile.type", [format_int(i, 10)]), "value": "RuntimeDefault"}]

	msga := {
		"alertMessage": sprintf("Pod: %v does not define seccompProfile as RuntimeDefault", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not define seccompProfile as RuntimeDefault
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    spec := wl.spec.template.spec
	seccompProfile_not_defined_well(spec)
    container := wl.spec.template.spec.containers[i]
    seccompProfile_not_defined_well(container)

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].securityContext.seccompProfile.type", [format_int(i, 10)]), "value": "RuntimeDefault"}]

	msga := {
		"alertMessage": sprintf("Workload: %v does not define seccompProfile as RuntimeDefault", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if CronJob does not define seccompProfile as RuntimeDefault
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    spec := wl.spec.jobTemplate.spec.template.spec
	seccompProfile_not_defined_well(spec)
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    seccompProfile_not_defined_well(container)

	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].securityContext.seccompProfile.type", [format_int(i, 10)]), "value": "RuntimeDefault"}]

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not define seccompProfile as RuntimeDefault", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

seccompProfile_not_defined_well(spec){
	not spec.securityContext.seccompProfile.type
}

seccompProfile_not_defined_well(spec){
	spec.securityContext.seccompProfile.type != "RuntimeDefault"
}