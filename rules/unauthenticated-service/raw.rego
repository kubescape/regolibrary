package armo_builtins

deny[msga] {
    service := input[_]
    service.kind == "Service"

    hasUnauthenticatedService(service)

    service_name := service.metadata.name
    
    path := "spec.ports"

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

hasUnauthenticatedService(service) {
    service.kind == "Service"
    service_name := service.metadata.name
    # Get the index and port
    port := service.spec.ports[]

    networkscanner.isUnauthenticatedService(service_name, port.port)
}