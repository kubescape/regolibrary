package armo_builtins


################################################################################
# Rules
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]

	begginingOfPath := "spec"
	alertInfo := evaluateWorkloadNonRootContainer(container, pod, begginingOfPath)
	fixPath := getFixedPath(alertInfo, i)
    failedPath := getFailedPath(alertInfo, i) 

    msga := {
		"alertMessage": sprintf("container: %v in pod: %v  may run as root", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failedPath,
        "fixPaths": fixPath,
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

	begginingOfPath := "spec.template.spec"
	alertInfo := evaluateWorkloadNonRootContainer(container, wl.spec.template, begginingOfPath)
	fixPath := getFixedPath(alertInfo, i)
    failedPath := getFailedPath(alertInfo, i) 
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failedPath,
        "fixPaths": fixPath,
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

	begginingOfPath := "spec.jobTemplate.spec.template"
	alertInfo := evaluateWorkloadNonRootContainer(container, wl.spec.jobTemplate.spec.template, begginingOfPath)
	fixPath := getFixedPath(alertInfo, i)
    failedPath := getFailedPath(alertInfo, i) 
	

    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failedPath,
        "fixPaths": fixPath,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

getFailedPath(alertInfo, i) = [replace(alertInfo.failedPath,"container_ndx",format_int(i,10))] {
	alertInfo.failedPath != ""
} else = []


getFixedPath(alertInfo, i) = [{"path":replace(alertInfo.fixPath[0].path,"container_ndx",format_int(i,10)), "value":alertInfo.fixPath[0].value}, {"path":replace(alertInfo.fixPath[1].path,"container_ndx",format_int(i,10)), "value":alertInfo.fixPath[1].value}]{
	count(alertInfo.fixPath) == 2
} else = [{"path":replace(alertInfo.fixPath[0].path,"container_ndx",format_int(i,10)), "value":alertInfo.fixPath[0].value}] {
	count(alertInfo.fixPath) == 1
}  else = []

#################################################################################
# Workload evaluation 

evaluateWorkloadNonRootContainer(container, pod, begginingOfPath) = alertInfo {
	runAsNonRootValue := getRunAsNonRootValue(container, pod, begginingOfPath)
	runAsNonRootValue.value == false
	
	runAsUserValue := getRunAsUserValue(container, pod, begginingOfPath)
	runAsUserValue.value == 0

	alertInfo := chooseFirstIfDefined(runAsUserValue, runAsNonRootValue)
} else = alertInfo {
    allowPrivilegeEscalationValue := getAllowPrivilegeEscalation(container, pod, begginingOfPath)
    allowPrivilegeEscalationValue.value == true

    alertInfo := allowPrivilegeEscalationValue
}


#################################################################################
# Value resolution functions


getRunAsNonRootValue(container, pod, begginingOfPath) = runAsNonRoot {
    failedPath := sprintf("%v.container[container_ndx].securityContext.runAsNonRoot", [begginingOfPath]) 
    runAsNonRoot := {"value" : container.securityContext.runAsNonRoot, "failedPath" : failedPath, "fixPath": [] ,"defined" : true}
} else = runAsNonRoot {
	failedPath := sprintf("%v.securityContext.runAsNonRoot", [begginingOfPath]) 
    runAsNonRoot := {"value" : pod.spec.securityContext.runAsNonRoot,  "failedPath" : failedPath, "fixPath": [], "defined" : true}
} else = {"value" : false,  "failedPath" : "", "fixPath": [{"path": "spec.securityContext.runAsNonRoot", "value":"true"}], "defined" : false} {
	isAllowPrivilegeEscalationField(container, pod)
} else = {"value" : false,  "failedPath" : "", "fixPath": [{"path":  sprintf("%v.securityContext.runAsNonRoot", [begginingOfPath]) , "value":"true"}, {"path":sprintf("%v.securityContext.allowPrivilegeEscalation", [begginingOfPath]), "value":"false"}], "defined" : false}

getRunAsUserValue(container, pod, begginingOfPath) = runAsUser {
	failedPath := sprintf("%v.container[container_ndx].securityContext.runAsUser", [begginingOfPath]) 
    runAsUser := {"value" : container.securityContext.runAsUser,  "failedPath" : failedPath,  "fixPath": [], "defined" : true}
} else = runAsUser {
	failedPath := sprintf("%v.securityContext.runAsUser", [begginingOfPath]) 
    runAsUser := {"value" : pod.spec.securityContext.runAsUser,  "failedPath" : failedPath, "fixPath": [],"defined" : true}
} else = {"value" : 0, "failedPath": "", "fixPath": [{"path":  sprintf("%v.securityContext.runAsNonRoot", [begginingOfPath]), "value":"true"}],"defined" : false}{
	isAllowPrivilegeEscalationField(container, pod)
} else = {"value" : 0, "failedPath": "", 
	"fixPath": [{"path":  sprintf("%v.securityContext.runAsNonRoot", [begginingOfPath]), "value":"true"},{"path":  sprintf("%v.securityContext.allowPrivilegeEscalation", [begginingOfPath]), "value":"false"}],
	"defined" : false}

getRunAsGroupValue(container, pod, begginingOfPath) = runAsGroup {
	failedPath := sprintf("%v.container[container_ndx].securityContext.runAsGroup", [begginingOfPath])
    runAsGroup := {"value" : container.securityContext.runAsGroup,  "failedPath" : failedPath, "fixPath": [],"defined" : true}
} else = runAsGroup {
	failedPath := sprintf("%v.securityContext.runAsGroup", [begginingOfPath])
    runAsGroup := {"value" : pod.spec.securityContext.runAsGroup,  "failedPath" : failedPath, "fixPath":[], "defined" : true}
} else = {"value" : 0, "failedPath": "", "fixPath": [{"path": "spec.securityContext.runAsNonRoot", "value":"true"}], "defined" : false}{
	isAllowPrivilegeEscalationField(container, pod)
} else = {"value" : 0, "failedPath": "", 
	"fixPath": [{"path": sprintf("%v.securityContext.runAsNonRoot", [begginingOfPath]), "value":"true"},{"path": sprintf("%v.securityContext.allowPrivilegeEscalation", [begginingOfPath]), "value":"false"}],
 	"defined" : false
}

getAllowPrivilegeEscalation(container, pod, begginingOfPath) = allowPrivilegeEscalation {
	failedPath := sprintf("%v.container[container_ndx].securityContext.allowPrivilegeEscalation", [begginingOfPath])
    allowPrivilegeEscalation := {"value" : container.securityContext.allowPrivilegeEscalation,  "failedPath" : failedPath, "fixPath": [],"defined" : true}
} else = allowPrivilegeEscalation {
	failedPath := sprintf("%v.securityContext.allowPrivilegeEscalation", [begginingOfPath])
    allowPrivilegeEscalation := {"value" : pod.spec.securityContext.allowPrivilegeEscalation,  "failedPath" : failedPath, "fixPath": [],"defined" : true}
} else = {"value" : true, "failedPath": "", "fixPath": [{"path": sprintf("%v.securityContext.allowPrivilegeEscalation", [begginingOfPath]), "value":"false"}], "defined" : false}

chooseFirstIfDefined(l1, l2) = c {
    l1.defined
    c := l1
} else = l2


isAllowPrivilegeEscalationField(container, pod) {
	container.securityContext.allowPrivilegeEscalation == false
}

isAllowPrivilegeEscalationField(container, pod) {
	pod.spec.securityContext.allowPrivilegeEscalation == false
}


