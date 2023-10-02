package armo_builtins

import data.kubernetes.api.client

# loadbalancer
deny[msga] {
	service := 	input[_]
	service.kind == "Service"
	service.spec.type == "LoadBalancer"

	wl := input[_]
	workload_types = {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "Pod", "CronJob"}
	workload_types[wl.kind]
	result := wl_connectedto_service(wl, service)

    # see default-config-inputs.json for list values
    services_names := data.postureControlInputs.servicesNames
	services_names[service.metadata.name]
    # externalIP := service.spec.externalIPs[_]
	externalIP := service.status.loadBalancer.ingress[0].ip


	msga := {
		"alertMessage": sprintf("service: %v is exposed", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": result,
		"failedPaths": result,
		"alertObject": {
			"k8sApiObjects": [wl, service]
		}
	}
}


# nodePort
# get a pod connected to that service, get nodeIP (hostIP?)
# use ip + nodeport
deny[msga] {
	service := 	input[_]
	service.kind == "Service"
	service.spec.type == "NodePort"

    # see default-config-inputs.json for list values
    services_names := data.postureControlInputs.servicesNames
	services_names[service.metadata.name]

	pod := input[_]
	pod.kind == "Pod"

	result := wl_connectedto_service(pod, service)



	msga := {
		"alertMessage": sprintf("service: %v is exposed", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": result,
		"failedPaths": result,
		"alertObject": {
			"k8sApiObjects": [pod, service]
		}
	}
}

# nodePort
# get a workload connected to that service, get nodeIP (hostIP?)
# use ip + nodeport
deny[msga] {
	service := 	input[_]
	service.kind == "Service"
	service.spec.type == "NodePort"

    # see default-config-inputs.json for list values
    services_names := data.postureControlInputs.servicesNames
	services_names[service.metadata.name]

	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}
	spec_template_spec_patterns[wl.kind]

	result := wl_connectedto_service(wl, service)

	pods_resource := client.query_all("pods")
	pod := pods_resource.body.items[_]
	my_pods := [pod | startswith(pod.metadata.name, wl.metadata.name)]



	msga := {
		"alertMessage": sprintf("service: %v is exposed", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": result,
		"failedPaths": result,
		"alertObject": {
			"k8sApiObjects": [wl, service]
		}
	}
}

# ====================================================================================

wl_connectedto_service(wl, service) = paths{
	count({x | service.spec.selector[x] == wl.metadata.labels[x]}) == count(service.spec.selector)
	paths = ["spec.selector.matchLabels", "service.spec.selector"]
}

wl_connectedto_service(wl, service) = paths {
	wl.spec.selector.matchLabels == service.spec.selector
	paths = ["spec.selector.matchLabels", "service.spec.selector"]
}
