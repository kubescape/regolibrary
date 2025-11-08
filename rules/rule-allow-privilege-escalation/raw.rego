package armo_builtins

import rego.v1

# Fails if pod has container  that allow privilege escalation
deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	start_of_path := "spec."
	is_allow_privilege_escalation_container(container)
	fixPath := get_fix_path(i, start_of_path)

	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  allow privilege escalation", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPath,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload has a container that allow privilege escalation
deny contains msga if {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	start_of_path := "spec.template.spec."
	is_allow_privilege_escalation_container(container)
	fixPath := get_fix_path(i, start_of_path)

	msga := {
		"alertMessage": sprintf("container :%v in %v: %v  allow privilege escalation", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPath,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob has a container that allow privilege escalation
deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	start_of_path := "spec.jobTemplate.spec.template.spec."
	is_allow_privilege_escalation_container(container)
	fixPath := get_fix_path(i, start_of_path)

	msga := {
		"alertMessage": sprintf("container :%v in %v: %v allow privilege escalation", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPath,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

is_allow_privilege_escalation_container(container) if {
	not container.securityContext.allowPrivilegeEscalation == false
	not container.securityContext.allowPrivilegeEscalation == true
	psps := [psp | psp = input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) == 0
}

is_allow_privilege_escalation_container(container) if {
	not container.securityContext.allowPrivilegeEscalation == false
	not container.securityContext.allowPrivilegeEscalation == true
	psps := [psp | psp = input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) > 0
	psp := psps[_]
	not psp.spec.allowPrivilegeEscalation == false
}

is_allow_privilege_escalation_container(container) if {
	container.securityContext.allowPrivilegeEscalation == true
	psps := [psp | psp = input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) == 0
}

is_allow_privilege_escalation_container(container) if {
	container.securityContext.allowPrivilegeEscalation == true
	psps := [psp | psp = input[_]; psp.kind == "PodSecurityPolicy"]
	count(psps) > 0
	psp := psps[_]
	not psp.spec.allowPrivilegeEscalation == false
}

get_fix_path(i, start_of_path) := [
	{"path": sprintf("%vcontainers[%v].securityContext.allowPrivilegeEscalation", [start_of_path, i]), "value": "false"},
	{"path": sprintf("%vcontainers[%v].securityContext.privileged", [start_of_path, i]), "value": "false"},
]
