# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	ingress := input[_]
	ingress.kind == "Ingress"
	path := ingress.spec.rules[i].http.paths[j]
	service_name := object.get(path.backend, "service", {}).name
	namespace := object.get(ingress.metadata, "namespace", "default")

	not service_exists(service_name, namespace, input)

	msga := {
		"alertMessage": sprintf("Ingress '%v' backend Service '%v' does not exist in namespace '%v'", [ingress.metadata.name, service_name, namespace]),
		"packagename": "armo_builtins",
		"failedPaths": [sprintf("spec.rules[%d].http.paths[%d].backend.service.name", [i, j])],
		"fixPaths": [],
		"alertScore": 4,
		"alertObject": {"k8sApiObjects": [ingress]},
	}
}

deny contains msga if {
	ingress := input[_]
	ingress.kind == "Ingress"
	service_name := object.get(ingress.spec, "defaultBackend", {}).service.name
	namespace := object.get(ingress.metadata, "namespace", "default")

	not service_exists(service_name, namespace, input)

	msga := {
		"alertMessage": sprintf("Ingress '%v' defaultBackend Service '%v' does not exist in namespace '%v'", [ingress.metadata.name, service_name, namespace]),
		"packagename": "armo_builtins",
		"failedPaths": ["spec.defaultBackend.service.name"],
		"fixPaths": [],
		"alertScore": 4,
		"alertObject": {"k8sApiObjects": [ingress]},
	}
}

service_exists(name, namespace, resources) if {
	svc := resources[_]
	svc.kind == "Service"
	object.get(svc.metadata, "namespace", "default") == namespace
	svc.metadata.name == name
}
