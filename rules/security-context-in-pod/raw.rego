package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[_]
    isNotSecurityContext(pod, container)
    msga := {
		"alertMessage": sprintf("Container: %v in pod: %v does not define a securityContext.", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}	
}



deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[_]
    isNotSecurityContext(wl.spec.template, container)
	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v does not define a securityContext.", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[_]
    isNotSecurityContext(wl.spec.jobTemplate.spec.template, container)
    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v does not define a securityContext.", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



isNotSecurityContext(pod, container) {
   count(pod.spec.securityContext) == 0
   not container.securityContext
}

isNotSecurityContext(pod, container) {
   count(pod.spec.securityContext) == 0
  	count(container.securityContext) == 0
}