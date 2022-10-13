package armo_builtins

# Fails if pod does not define seccompProfile
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    spec := pod.spec
	seccompProfile_not_defined(spec)
    container := pod.spec.containers[i]
    seccompProfile_not_defined(container)

	fixPaths := [{"path": sprintf("spec.containers[%v].securityContext.seccompProfile", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Pod: %v does not define seccompProfile", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not define seccompProfile
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    spec := wl.spec.template.spec
	seccompProfile_not_defined(spec)
    container := wl.spec.template.spec.containers[i]
    seccompProfile_not_defined(container)

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].securityContext.seccompProfile", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Workload: %v does not define seccompProfile", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if CronJob does not define seccompProfile
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    spec := wl.spec.jobTemplate.spec.template.spec
	seccompProfile_not_defined(spec)
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    seccompProfile_not_defined(container)

	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].securityContext.seccompProfile", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not define seccompProfile", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

seccompProfile_not_defined(spec){
	not spec.securityContext.seccompProfile
}