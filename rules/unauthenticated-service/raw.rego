package armo_builtins

deny[msga] {

    service := input[_]
    service.kind == "Service"

    service_name := service.metadata.name

    # Get the index and port
    port := service.spec.ports[i]

    networkscanner.isUnauthenticatedService(service_name, port.port)

    path := sprintf("spec.ports[%v].port", i)

	msga := {
		"alertMessage": sprintf("service is unauthenticated: %s in port %v", service_name, port.port),
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