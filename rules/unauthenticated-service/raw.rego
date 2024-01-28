package armo_builtins

deny[msga] {
    service := input[_]
    service.kind == "Service"

    specificPort := service.spec.ports[i]
    portNumber := specificPort.port
    service_name := service.metadata.name
    hasUnauthenticatedService(service_name, portNumber)
    
    path := sprintf("spec.ports[%v].port", [i])

	msga := {
		"alertMessage": sprintf("Unauthenticated service %v", service_name),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [service]
		},
	}
}

hasUnauthenticatedService(service_name, port) {
    networkscanner.isUnauthenticatedService(service_name, port)
}