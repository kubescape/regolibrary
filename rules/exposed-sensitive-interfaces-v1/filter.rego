# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

import data.kubernetes.api.client

deny contains msga if {
	wl_names := data.postureControlInputs.sensitiveInterfaces
	wl := input[_]
	workload_types = {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "Pod", "CronJob"}
	workload_types[wl.kind]

	# see default-config-inputs.json for list values
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	srvc := get_wl_connectedto_service(wl)

	wlvector = {
		"name": wl.metadata.name,
		"namespace": wl.metadata.namespace,
		"kind": wl.kind,
		"relatedObjects": srvc,
	}

	msga := {
		"alertMessage": sprintf("wl: %v is in the cluster", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector,
		},
	}
}

get_wl_connectedto_service(wl) := services if {
	services := [service |
		service := input[_]
		service.kind == "Service"
		wl_connectedto_service(wl, service)
	]
}

wl_connectedto_service(wl, service) if {
	wl.metadata.namespace == service.metadata.namespace
	count(service.spec.selector) > 0
	count({key | service.spec.selector[key] == wl.metadata.labels[key]}) == count(service.spec.selector)
}
