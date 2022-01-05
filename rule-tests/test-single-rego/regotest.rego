package armo_builtins


# Fails if pod does not define linux security hardening 
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    isUnsafePod(pod)
    container := pod.spec.containers[_]
    isUnsafeContainer(container)
 
	path := "spec.securityContext"
	msga := {
		"alertMessage": sprintf("Pod: %v does not define any linux security hardening", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not define linux security hardening 
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    isUnsafeWorkload(wl)
    container := wl.spec.template.spec.containers[_]
    isUnsafeContainer(container)

	path := "spec.template.spec.securityContext"
	msga := {
		"alertMessage": sprintf("Workload: %v does not define any linux security hardening", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if pod does not define linux security hardening 
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    isUnsafeCronJob(wl)
	container = wl.spec.jobTemplate.spec.template.spec.containers[_]
    isUnsafeContainer(container)

	path := "spec.jobTemplate.spec.template.spec.securityContext"
	msga := {
		"alertMessage": sprintf("Cronjob: %v does not define any linux security hardening", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

isUnsafePod(pod){
    not pod.spec.securityContext.seccompProfile
    not pod.spec.securityContext.seLinuxOptions
	annotations := [pod.metadata.annotations[i] | annotaion = i; startswith(i, "container.apparmor.security.beta.kubernetes.io")]
	not count(annotations) > 0
}

isUnsafeContainer(container){
    not container.securityContext.seccompProfile
    not container.securityContext.seLinuxOptions
    not container.securityContext.capabilities.drop
}

isUnsafeWorkload(wl) {
    not wl.spec.template.spec.securityContext.seccompProfile
    not wl.spec.template.spec.securityContext.seLinuxOptions
	annotations := [wl.spec.template.metadata.annotations[i] | annotaion = i; startswith(i, "container.apparmor.security.beta.kubernetes.io")]
	not count(annotations) > 0
}

isUnsafeCronJob(cronjob) {
    not cronjob.spec.jobTemplate.spec.template.spec.securityContext.seccompProfile
    not cronjob.spec.jobTemplate.spec.template.spec.securityContext.seLinuxOptions
	annotations := [cronjob.spec.jobTemplate.spec.template.metadata.annotations[i] | annotaion = i; startswith(i, "container.apparmor.security.beta.kubernetes.io")]
	not count(annotations) > 0
}

