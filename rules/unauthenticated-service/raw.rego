package armo_builtins

import future.keywords.contains
import future.keywords.if

deny contains msga if {
	service := input[_]
	service.kind == "Service"

	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
	spec_template_spec_patterns[wl.kind]
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
