package armo_builtins


################################################################################
# Rules
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]

	alertInfo := evaluateWorkloadNonRootContainer(container, pod)

    msga := {
		"alertMessage": sprintf("container: %v in pod: %v  may run as root", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [replace(alertInfo.path,"container_ndx",format_int(i,10))],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}


deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]

	alertInfo := evaluateWorkloadNonRootContainer(container, wl.spec.template)
	
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [concat(".",["spec.template",replace(alertInfo.path,"container_ndx",format_int(i,10))])],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob has a container configured to run as root
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]

	alertInfo := evaluateWorkloadNonRootContainer(container, wl.spec.jobTemplate.spec.template)
	
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [concat(".",["spec.jobTemplate.spec.template",replace(alertInfo.path,"container_ndx",format_int(i,10))])],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

#################################################################################
# Workload evaluation 

evaluateWorkloadNonRootContainer(container, pod) = alertInfo {
	runAsNonRootValue := getRunAsNonRootValue(container, pod)
	runAsNonRootValue.value == false
	
	runAsUserValue := getRunAsUserValue(container, pod)
	runAsUserValue.value == 0

	alertInfo := chooseFirstIfDefined(runAsUserValue, runAsNonRootValue)
} else = alertInfo {
    allowPrivilegeEscalationValue := getAllowPrivilegeEscalation(container, pod)
    allowPrivilegeEscalationValue.value == true

    alertInfo := allowPrivilegeEscalationValue
}


#################################################################################
# Value resolution functions

getRunAsNonRootValue(container, pod) = runAsNonRoot {
    path := "spec.container[container_ndx].securityContext.runAsNonRoot"
    runAsNonRoot := {"value" : container.securityContext.runAsNonRoot, "path" : path, "defined" : true}
} else = runAsNonRoot {
    path := "spec.securityContext.runAsNonRoot"
    runAsNonRoot := {"value" : pod.spec.securityContext.runAsNonRoot, "path" : path, "defined" : true}
} else = {"value" : false, "path": "spec", "defined" : false}

getRunAsUserValue(container, pod) = runAsUser {
    path := "spec.container[container_ndx].securityContext.runAsUser"
    runAsUser := {"value" : container.securityContext.runAsUser, "path" : path, "defined" : true}
} else = runAsUser {
    path := "spec.securityContext.runAsUser"
    runAsUser := {"value" : pod.spec.securityContext.runAsUser, "path" : path, "defined" : true}
} else = {"value" : 0, "path": "spec", "defined" : false}

getRunAsGroupValue(container, pod) = runAsGroup {
    path := "spec.container[container_ndx].securityContext.runAsGroup"
    runAsGroup := {"value" : container.securityContext.runAsGroup, "path" : path, "defined" : true}
} else = runAsGroup {
    path := "spec.securityContext.runAsGroup"
    runAsGroup := {"value" : pod.spec.securityContext.runAsGroup, "path" : path, "defined" : true}
} else = {"value" : 0, "path": "spec", "defined" : false}

getAllowPrivilegeEscalation(container, pod) = allowPrivilegeEscalation {
    path := "spec.container[container_ndx].securityContext.allowPrivilegeEscalation"
    allowPrivilegeEscalation := {"value" : container.securityContext.allowPrivilegeEscalation, "path" : path, "defined" : true}
} else = allowPrivilegeEscalation {
    path := "spec.securityContext.allowPrivilegeEscalation"
    allowPrivilegeEscalation := {"value" : pod.spec.securityContext.allowPrivilegeEscalation, "path" : path, "defined" : true}
} else = {"value" : true, "path": "spec", "defined" : false}

chooseFirstIfDefined(l1, l2) = c {
    l1.defined
    c := l1
} else = l2