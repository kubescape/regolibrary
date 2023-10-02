package armo_builtins

import data.kubernetes.api.client

# loadbalancer
deny[msga] {
	wl := input[_]
	workload_types = {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "Pod", "CronJob"}
	workload_types[wl.kind]

    # see default-config-inputs.json for list values
    wl_names := data.postureControlInputs.sensitiveInterfaces
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	service := 	input[_]
	service.kind == "Service"
	service.spec.type == "LoadBalancer"

	result := wl_connectedto_service(wl, service)

    # externalIP := service.spec.externalIPs[_]
	externalIP := service.status.loadBalancer.ingress[0].ip

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": [service]}

	msga := {
		"alertMessage": sprintf("service: %v is exposed", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": result,
		"failedPaths": result,
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": wlvector
		}
	}
}


# nodePort
# get a pod connected to that service, get nodeIP (hostIP?)
# use ip + nodeport
deny[msga] {
	wl := input[_]
	wl.kind == "Pod"

    # see default-config-inputs.json for list values
    wl_names := data.postureControlInputs.sensitiveInterfaces
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	service := 	input[_]
	service.kind == "Service"
	service.spec.type == "NodePort"

	result := wl_connectedto_service(wl, service)

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": [service]}

	msga := {
		"alertMessage": sprintf("service: %v is exposed", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": result,
		"failedPaths": result,
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": wlvector
		}
	}
}

# nodePort
# get a workload connected to that service, get nodeIP (hostIP?)
# use ip + nodeport
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}
	spec_template_spec_patterns[wl.kind]

    # see default-config-inputs.json for list values
    wl_names := data.postureControlInputs.sensitiveInterfaces
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	service := 	input[_]
	service.kind == "Service"
	service.spec.type == "NodePort"

	result := wl_connectedto_service(wl, service)

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": [service]}

	msga := {
		"alertMessage": sprintf("service: %v is exposed", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": result,
		"failedPaths": result,
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": wlvector
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