package armo_builtins


# Fails if pod has container  that allow privilege escalation
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	begginingOfPath := "spec."
    result := isAllowPrivilegeEscalationContainer(container, i, begginingOfPath)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  allow privilege escalation", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}


# Fails if workload has a container that allow privilege escalation
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
	begginingOfPath := "spec.template.spec."
    result := isAllowPrivilegeEscalationContainer(container, i, begginingOfPath)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  allow privilege escalation", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if cronjob has a container that allow privilege escalation
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
	result := isAllowPrivilegeEscalationContainer(container, i, begginingOfPath)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v allow privilege escalation", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



isAllowPrivilegeEscalationContainer(container, i, begginingOfPath) = path {
	path = ""
    not container.securityContext.allowPrivilegeEscalation == false
	not container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) == 0
	path = ""
}

isAllowPrivilegeEscalationContainer(container, i, begginingOfPath)  = path {
	path = ""
    not container.securityContext.allowPrivilegeEscalation == false
	not container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) > 0
	psp := psps[_]
	not psp.spec.allowPrivilegeEscalation == false
	path = ""
}


isAllowPrivilegeEscalationContainer(container, i, begginingOfPath)  = path {
	path = ""
    container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) == 0
	path = sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [begginingOfPath, format_int(i, 10)])
}

isAllowPrivilegeEscalationContainer(container, i, begginingOfPath) = path {
	path = ""
    container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) > 0
	psp := psps[_]
	not psp.spec.allowPrivilegeEscalation == false
	path = sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [begginingOfPath, format_int(i, 10)])
}


