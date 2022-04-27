package armo_builtins


# Fails if pod does not define linux security hardening 
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    is_unsafe_pod(pod)
    container := pod.spec.containers[i]
    is_unsafe_container(container)

	fixPaths := [
	{"path": sprintf("spec.containers[%v].seccompProfile", [format_int(i, 10)]), "value": "YOUR_VALUE"},
	{"path": sprintf("spec.containers[%v].seLinuxOptions", [format_int(i, 10)]), "value": "YOUR_VALUE"},
	{"path": sprintf("spec.containers[%v].capabilities.drop", [format_int(i, 10)]), "value": "YOUR_VALUE"}
	]

	msga := {
		"alertMessage": sprintf("Pod: %v does not define any linux security hardening", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
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
    is_unsafe_workload(wl)
    container := wl.spec.template.spec.containers[i]
    is_unsafe_container(container)

	fixPaths := [
	{"path": sprintf("spec.template.spec.containers[%v].seccompProfile", [format_int(i, 10)]), "value": "YOUR_VALUE"},
	{"path": sprintf("spec.template.spec.containers[%v].seLinuxOptions", [format_int(i, 10)]), "value": "YOUR_VALUE"},
	{"path": sprintf("spec.template.spec.containers[%v].capabilities.drop", [format_int(i, 10)]), "value": "YOUR_VALUE"}
	]


	msga := {
		"alertMessage": sprintf("Workload: %v does not define any linux security hardening", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if pod does not define linux security hardening 
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    is_unsafe_cronjob(wl)
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    is_unsafe_container(container)

	fixPaths := [
	{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].seccompProfile", [format_int(i, 10)]), "value": "YOUR_VALUE"},
	{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].seLinuxOptions", [format_int(i, 10)]), "value": "YOUR_VALUE"},
	{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].capabilities.drop", [format_int(i, 10)]), "value": "YOUR_VALUE"}
	]

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not define any linux security hardening", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

is_unsafe_pod(pod){
    not pod.spec.securityContext.seccompProfile
    not pod.spec.securityContext.seLinuxOptions
	annotations := [pod.metadata.annotations[i] | annotation = i; startswith(i, "container.apparmor.security.beta.kubernetes.io")]
	not count(annotations) > 0
}

is_unsafe_container(container){
    not container.securityContext.seccompProfile
    not container.securityContext.seLinuxOptions
    not container.securityContext.capabilities.drop
}

is_unsafe_workload(wl) {
    not wl.spec.template.spec.securityContext.seccompProfile
    not wl.spec.template.spec.securityContext.seLinuxOptions
	annotations := [wl.spec.template.metadata.annotations[i] | annotation = i; startswith(i, "container.apparmor.security.beta.kubernetes.io")]
	not count(annotations) > 0
}

is_unsafe_cronjob(cronjob) {
    not cronjob.spec.jobTemplate.spec.template.spec.securityContext.seccompProfile
    not cronjob.spec.jobTemplate.spec.template.spec.securityContext.seLinuxOptions
	annotations := [cronjob.spec.jobTemplate.spec.template.metadata.annotations[i] | annotation = i; startswith(i, "container.apparmor.security.beta.kubernetes.io")]
	not count(annotations) > 0
}

