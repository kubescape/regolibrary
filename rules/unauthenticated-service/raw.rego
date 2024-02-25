package armo_builtins

deny[msga] {

	service := input[_]
    service.kind == "Service"

	wl := input[_]
    spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
    spec_template_spec_patterns[wl.kind]
    wl_connected_to_service(wl, service)

    specificPort := service.spec.ports[i]
    portNumber := specificPort.port
    service_name := service.metadata.name
	namespace := service.metadata.namespace
    hasUnauthenticatedService(service_name, portNumber, namespace)
    
	# Path to the pod spec
    path := "spec"

	msga := {
		"alertMessage": sprintf("Unauthenticated service %v which exposes %v", [service_name, wl.metadata.name]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		},
		"relatedObjects": [{
            "object": service
        }]
	}
}

hasUnauthenticatedService(service_name, port, namespace) {
    networkscanner.isUnauthenticatedService(service_name, port, namespace)
}

wl_connected_to_service(wl, svc) {
    count({x | svc.spec.selector[x] == wl.metadata.labels[x]}) == count(svc.spec.selector)
}

wl_connected_to_service(wl, svc) {
    wl.spec.selector.matchLabels == svc.spec.selector
}
