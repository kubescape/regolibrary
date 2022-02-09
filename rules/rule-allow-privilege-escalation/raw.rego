package armo_builtins


# Fails if pod has container  that allow privilege escalation
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	begginingOfPath := "spec."
    result := isAllowPrivilegeEscalationContainer(container, i, begginingOfPath)
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  allow privilege escalation", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failedPath,
		"fixPaths": fixedPath,
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
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  allow privilege escalation", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failedPath,
		"fixPaths": fixedPath,
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
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

    msga := {
		"alertMessage": sprintf("container :%v in %v: %v allow privilege escalation", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failedPath,
		"fixPaths": fixedPath,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



isAllowPrivilegeEscalationContainer(container, i, begginingOfPath) = [failedPath, fixPath] {
    not container.securityContext.allowPrivilegeEscalation == false
	not container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) == 0
	failedPath = ""
	fixPath = {"path": sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [begginingOfPath, format_int(i, 10)]), "value":"false"} 
}

isAllowPrivilegeEscalationContainer(container, i, begginingOfPath) = [failedPath, fixPath] {
    not container.securityContext.allowPrivilegeEscalation == false
	not container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) > 0
	psp := psps[_]
	not psp.spec.allowPrivilegeEscalation == false
	failedPath = ""
	fixPath = {"path": sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [begginingOfPath, format_int(i, 10)]), "value":"false"} 
}


isAllowPrivilegeEscalationContainer(container, i, begginingOfPath) = [failedPath, fixPath]  {
    container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) == 0
	fixPath = ""
	failedPath = sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [begginingOfPath, format_int(i, 10)])
}

isAllowPrivilegeEscalationContainer(container, i, begginingOfPath)= [failedPath, fixPath] {
    container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) > 0
	psp := psps[_]
	not psp.spec.allowPrivilegeEscalation == false
	fixPath = ""
	failedPath = sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [begginingOfPath, format_int(i, 10)])
}

 getFailedPath(paths) = [paths[0]] {
	paths[0] != ""
} else = []


getFixedPath(paths) = [paths[1]] {
	paths[1] != ""
} else = []

