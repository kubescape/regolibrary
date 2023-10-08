package armo_builtins

# input: pod
# apiversion: v1
# does:	returns the external facing services of that pod

deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	podns := pod.metadata.namespace
	podname := pod.metadata.name
	labels := pod.metadata.labels
	filtered_labels := json.remove(labels, ["pod-template-hash"])
    path := "metadata.labels"
	service := 	input[_]
	service.kind == "Service"
	service.metadata.namespace == podns
	service.spec.selector == filtered_labels
    
	hasSSHPorts(service)

	msga := {
		"alertMessage": sprintf("pod %v/%v exposed by SSH services: %v", [podns, podname, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
          "alertObject": {
			"k8sApiObjects": [pod,service]
		}
     }
}

deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	labels := wl.spec.template.metadata.labels
    path := "spec.template.metadata.labels"
	service := 	input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	service.spec.selector == labels

	hasSSHPorts(service)

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [wl,service]
		}
     }
}

deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	labels := wl.spec.jobTemplate.spec.template.metadata.labels
    path := "spec.jobTemplate.spec.template.metadata.labels"
	service := 	input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	service.spec.selector == labels

	hasSSHPorts(service)

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [wl,service]
		}
     }
}

hasSSHPorts(service) {
	port := service.spec.ports[_]
	port.port == 22
}


hasSSHPorts(service) {
	port := service.spec.ports[_]
	port.port == 2222
}

hasSSHPorts(service) {
	port := service.spec.ports[_]
	port.targetPort == 22
}


hasSSHPorts(service) {
	port := service.spec.ports[_]
	port.targetPort == 2222
}
