package armo_builtins


################################################################################
# Rules
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]

	beggining_of_path := "spec"
	alertInfo := evaluate_workload_non_root_container(container, pod, beggining_of_path)
	fixPath := get_fixed_path(alertInfo, i)
    failed_path := get_failed_path(alertInfo, i) 

    msga := {
		"alertMessage": sprintf("container: %v in pod: %v  may run as root", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
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

	beggining_of_path := "spec.template.spec"
	alertInfo := evaluate_workload_non_root_container(container, wl.spec.template, beggining_of_path)
	fixPath := get_fixed_path(alertInfo, i)
    failed_path := get_failed_path(alertInfo, i) 
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
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

	beggining_of_path := "spec.jobTemplate.spec.template.spec"
	alertInfo := evaluate_workload_non_root_container(container, wl.spec.jobTemplate.spec.template, beggining_of_path)
	fixPath := get_fixed_path(alertInfo, i)
    failed_path := get_failed_path(alertInfo, i) 
	

    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
        "fixPaths": fixPath,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

get_failed_path(alertInfo, i) = [replace(alertInfo.failed_path,"container_ndx",format_int(i,10))] {
	alertInfo.failed_path != ""
} else = []


get_fixed_path(alertInfo, i) = [{"path":replace(alertInfo.fixPath[0].path,"container_ndx",format_int(i,10)), "value":alertInfo.fixPath[0].value}, {"path":replace(alertInfo.fixPath[1].path,"container_ndx",format_int(i,10)), "value":alertInfo.fixPath[1].value}]{
	count(alertInfo.fixPath) == 2
} else = [{"path":replace(alertInfo.fixPath[0].path,"container_ndx",format_int(i,10)), "value":alertInfo.fixPath[0].value}] {
	count(alertInfo.fixPath) == 1
}  else = []

#################################################################################
# Workload evaluation 

evaluate_workload_non_root_container(container, pod, beggining_of_path) = alertInfo {
	runAsNonRootValue := get_run_as_non_root_value(container, pod, beggining_of_path)
	runAsNonRootValue.value == false
	
	runAsUserValue := get_run_as_user_value(container, pod, beggining_of_path)
	runAsUserValue.value == 0

	alertInfo := choose_first_if_defined(runAsUserValue, runAsNonRootValue)
} else = alertInfo {
    allowPrivilegeEscalationValue := get_allow_privilege_escalation(container, pod, beggining_of_path)
    allowPrivilegeEscalationValue.value == true

    alertInfo := allowPrivilegeEscalationValue
}


#################################################################################
# Value resolution functions


get_run_as_non_root_value(container, pod, beggining_of_path) = runAsNonRoot {
    failed_path := sprintf("%v.containerss[container_ndx].securityContext.runAsNonRoot", [beggining_of_path]) 
    runAsNonRoot := {"value" : container.securityContext.runAsNonRoot, "failed_path" : failed_path, "fixPath": [] ,"defined" : true}
} else = runAsNonRoot {
	failed_path := sprintf("%v.securityContext.runAsNonRoot", [beggining_of_path]) 
    runAsNonRoot := {"value" : pod.spec.securityContext.runAsNonRoot,  "failed_path" : failed_path, "fixPath": [], "defined" : true}
} else = {"value" : false,  "failed_path" : "", "fixPath": [{"path": sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [beggining_of_path]), "value":"true"}], "defined" : false} {
	is_allow_privilege_escalation_field(container, pod)
} else = {"value" : false,  "failed_path" : "", "fixPath": [{"path":  sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [beggining_of_path]) , "value":"true"}, {"path":sprintf("%v.containers[container_ndx].securityContext.allowPrivilegeEscalation", [beggining_of_path]), "value":"false"}], "defined" : false}

get_run_as_user_value(container, pod, beggining_of_path) = runAsUser {
	failed_path := sprintf("%v.containerss[container_ndx].securityContext.runAsUser", [beggining_of_path]) 
    runAsUser := {"value" : container.securityContext.runAsUser,  "failed_path" : failed_path,  "fixPath": [], "defined" : true}
} else = runAsUser {
	failed_path := sprintf("%v.securityContext.runAsUser", [beggining_of_path]) 
    runAsUser := {"value" : pod.spec.securityContext.runAsUser,  "failed_path" : failed_path, "fixPath": [],"defined" : true}
} else = {"value" : 0, "failed_path": "", "fixPath": [{"path":  sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [beggining_of_path]), "value":"true"}],"defined" : false}{
	is_allow_privilege_escalation_field(container, pod)
} else = {"value" : 0, "failed_path": "", 
	"fixPath": [{"path":  sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [beggining_of_path]), "value":"true"},{"path":  sprintf("%v.containers[container_ndx].securityContext.allowPrivilegeEscalation", [beggining_of_path]), "value":"false"}],
	"defined" : false}

get_run_as_group_value(container, pod, beggining_of_path) = runAsGroup {
	failed_path := sprintf("%v.containers[container_ndx].securityContext.runAsGroup", [beggining_of_path])
    runAsGroup := {"value" : container.securityContext.runAsGroup,  "failed_path" : failed_path, "fixPath": [],"defined" : true}
} else = runAsGroup {
	failed_path := sprintf("%v.securityContext.runAsGroup", [beggining_of_path])
    runAsGroup := {"value" : pod.spec.securityContext.runAsGroup,  "failed_path" : failed_path, "fixPath":[], "defined" : true}
} else = {"value" : 0, "failed_path": "", "fixPath": [{"path": sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [beggining_of_path]), "value":"true"}], "defined" : false}{
	is_allow_privilege_escalation_field(container, pod)
} else = {"value" : 0, "failed_path": "", 
	"fixPath": [{"path": sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [beggining_of_path]), "value":"true"},{"path": sprintf("%v.containers[container_ndx].securityContext.allowPrivilegeEscalation", [beggining_of_path]), "value":"false"}],
 	"defined" : false
}

get_allow_privilege_escalation(container, pod, beggining_of_path) = allowPrivilegeEscalation {
	failed_path := sprintf("%v.containers[container_ndx].securityContext.allowPrivilegeEscalation", [beggining_of_path])
    allowPrivilegeEscalation := {"value" : container.securityContext.allowPrivilegeEscalation,  "failed_path" : failed_path, "fixPath": [],"defined" : true}
} else = allowPrivilegeEscalation {
	failed_path := sprintf("%v.securityContext.allowPrivilegeEscalation", [beggining_of_path])
    allowPrivilegeEscalation := {"value" : pod.spec.securityContext.allowPrivilegeEscalation,  "failed_path" : failed_path, "fixPath": [],"defined" : true}
} else = {"value" : true, "failed_path": "", "fixPath": [{"path": sprintf("%v.containers[container_ndx].securityContext.allowPrivilegeEscalation", [beggining_of_path]), "value":"false"}], "defined" : false}

choose_first_if_defined(l1, l2) = c {
    l1.defined
    c := l1
} else = l2


is_allow_privilege_escalation_field(container, pod) {
	container.securityContext.allowPrivilegeEscalation == false
}

is_allow_privilege_escalation_field(container, pod) {
	pod.spec.securityContext.allowPrivilegeEscalation == false
}


