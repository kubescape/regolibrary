package armo_builtins

deny[msga] {

    service := input[_]
    service.kind == "Service"

    port := service.spec.ports[_]
    service_name := service.metadata.name

    networkscanner.unauthenticated_service(service_name, port.port)

    path := sprintf("spec.ports[%d]", port.index)

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