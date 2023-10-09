package armo_builtins


# Fails if pod has container  that allow privilege escalation
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	start_of_path := "spec."
    result := is_allow_privilege_escalation_container(container, i, start_of_path)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  allow privilege escalation", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
		"fixPaths": fixed_path,
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
	start_of_path := "spec.template.spec."
    result := is_allow_privilege_escalation_container(container, i, start_of_path)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  allow privilege escalation", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
		"fixPaths": fixed_path,
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
	start_of_path := "spec.jobTemplate.spec.template.spec."
	result := is_allow_privilege_escalation_container(container, i, start_of_path)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    msga := {
		"alertMessage": sprintf("container :%v in %v: %v allow privilege escalation", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
		"fixPaths": fixed_path,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



is_allow_privilege_escalation_container(container, i, start_of_path) = [failed_path, fixPath] {
    not container.securityContext.allowPrivilegeEscalation == false
	not container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) == 0
	failed_path = ""
	fixPath = {"path": sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [start_of_path, format_int(i, 10)]), "value":"false"} 
}

is_allow_privilege_escalation_container(container, i, start_of_path) = [failed_path, fixPath] {
    not container.securityContext.allowPrivilegeEscalation == false
	not container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) > 0
	psp := psps[_]
	not psp.spec.allowPrivilegeEscalation == false
	failed_path = ""
	fixPath = {"path": sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [start_of_path, format_int(i, 10)]), "value":"false"} 
}


is_allow_privilege_escalation_container(container, i, start_of_path) = [failed_path, fixPath]  {
    container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) == 0
	fixPath = ""
	failed_path = sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [start_of_path, format_int(i, 10)])
}

is_allow_privilege_escalation_container(container, i, start_of_path)= [failed_path, fixPath] {
    container.securityContext.allowPrivilegeEscalation == true
	psps := [psp |  psp= input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) > 0
	psp := psps[_]
	not psp.spec.allowPrivilegeEscalation == false
	fixPath = ""
	failed_path = sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [start_of_path, format_int(i, 10)])
}

 get_failed_path(paths) = [paths[0]] {
	paths[0] != ""
} else = []


get_fixed_path(paths) = [paths[1]] {
	paths[1] != ""
} else = []

