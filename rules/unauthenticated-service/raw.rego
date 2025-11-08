package armo_builtins

import rego.v1

deny contains msga if {
	service := input[_]
	service.kind == "Service"

	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
	spec_template_spec_patterns[wl.kind]
	is_same_namespace(wl, service)
	wl_connected_to_service(wl, service)

	service_scan_result := input[_]
	service_scan_result.kind == "ServiceScanResult"
	service_name := service.metadata.name
	has_unauthenticated_service(service_name, service.metadata.namespace, service_scan_result)

	msga := {
		"alertMessage": sprintf("Unauthenticated service %v exposes %v", [service_name, wl.metadata.name]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [],
		"failedPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

has_unauthenticated_service(service_name, namespace, service_scan_result) if {
	service_scan_result.metadata.name == service_name
	service_scan_result.metadata.namespace == namespace
	service_scan_result.spec.ports[_].authenticated == false
}

wl_connected_to_service(wl, svc) if {
	count({x | svc.spec.selector[x] == wl.metadata.labels[x]}) == count(svc.spec.selector)
}

wl_connected_to_service(wl, svc) if {
	wl.spec.selector.matchLabels == svc.spec.selector
}

is_same_namespace(metadata1, metadata2) if {
	metadata1.namespace == metadata2.namespace
}

is_same_namespace(metadata1, metadata2) if {
	not metadata1.namespace
	not metadata2.namespace
}

is_same_namespace(metadata1, metadata2) if {
	not metadata2.namespace
	metadata1.namespace == "default"
}

is_same_namespace(metadata1, metadata2) if {
	not metadata1.namespace
	metadata2.namespace == "default"
}
