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

	wlvector = {"name": pod.metadata.name,
				"namespace": pod.metadata.namespace,
				"kind": pod.kind,
				"relatedObjects": service}
	msga := {
		"alertMessage": sprintf("pod %v/%v exposed by SSH services: %v", [podns, podname, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
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

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": service}

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
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

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": service}

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
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
