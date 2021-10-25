package armo_builtins
# Deny mutating action unless user is in group owning the resource


#privileged pods
deny[msga] {

	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[_]
	isPrivilegedContainer(container)

    msga := {
		"alertMessage": sprintf("the following pods are defined as privileged: %v", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
         "alertObject": {
			"k8sApiObjects": [pod]
		}
     }
}


#handles majority of workload resources
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[_]
	isPrivilegedContainer(container)

    msga := {
		"alertMessage": sprintf("%v: %v is defined as privileged:", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

#handles cronjob
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[_]
	isPrivilegedContainer(container)

    msga := {
		"alertMessage": sprintf("the following cronjobs are defined as privileged: %v", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}


isPrivilegedContainer(container) {
	sysAdminCap := "SYS_ADMIN"
    contains(container.securityContext.capabilities.add[_], sysAdminCap)
}

isPrivilegedContainer(container) {
	container.securityContext.privileged == true
}