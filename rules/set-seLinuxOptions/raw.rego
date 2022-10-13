package armo_builtins


# Fails if pod does not define seLinuxOptions 
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    no_seLinuxOptions_in_securityContext(pod.spec)
    container := pod.spec.containers[i]
    no_seLinuxOptions_in_securityContext(container)

	fixPaths := [{"path": sprintf("spec.containers[%v].securityContext.seLinuxOptions", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Pod: %v does not define any seLinuxOptions", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not define seLinuxOptions
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    no_seLinuxOptions_in_securityContext(wl.spec.template.spec)
    container := wl.spec.template.spec.containers[i]
    no_seLinuxOptions_in_securityContext(container)

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].securityContext.seLinuxOptions", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Workload: %v does not define any seLinuxOptions", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if CronJob does not define seLinuxOptions 
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    no_seLinuxOptions_in_securityContext(wl.spec.jobTemplate.spec.template.spec)
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    no_seLinuxOptions_in_securityContext(container)

	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].securityContext.seLinuxOptions", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not define any seLinuxOptions", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

no_seLinuxOptions_in_securityContext(spec){
    not spec.securityContext.seLinuxOptions
}