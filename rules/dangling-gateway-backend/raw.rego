# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	route := input[_]
	route.kind in ["HTTPRoute", "TCPRoute", "UDPRoute"]
	ref := route.spec.rules[i].backendRefs[j]
	backend_is_service(ref)
	namespace := backend_namespace(ref, route)

	not service_exists(ref.name, namespace, input)

	msga := {
		"alertMessage": sprintf("%v '%v' backendRef '%v' does not exist in namespace '%v'", [route.kind, route.metadata.name, ref.name, namespace]),
		"packagename": "armo_builtins",
		"failedPaths": [sprintf("spec.rules[%d].backendRefs[%d].name", [i, j])],
		"fixPaths": [],
		"alertScore": 4,
		"alertObject": {"k8sApiObjects": [route]},
	}
}

# A backendRef is a Service reference unless kind/group say otherwise. kind
# defaults to "Service" and group defaults to "" (core). Non-Service backends
# (custom resources, other Gateway objects) are skipped offline.
backend_is_service(ref) if {
	object.get(ref, "kind", "Service") == "Service"
	object.get(ref, "group", "") == ""
}

backend_namespace(ref, route) := ns if {
	route_ns := object.get(route.metadata, "namespace", "default")
	ns := object.get(ref, "namespace", route_ns)
}

service_exists(name, namespace, resources) if {
	svc := resources[_]
	svc.kind == "Service"
	svc_namespace := object.get(svc.metadata, "namespace", "default")
	svc_namespace == namespace
	svc.metadata.name == name
}
