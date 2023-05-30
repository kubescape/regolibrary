package armo_builtins
import data.kubernetes.api.client as client
import data

deny[msga] {
	wl := input[_]
	workload_types = {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "Pod", "CronJob"}
	workload_types[wl.kind]

	# see default-config-inputs.json for list values
	wl_names := data.postureControlInputs.sensitiveInterfaces
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	srvc := get_wl_connectedto_service(wl)

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": srvc}

	msga := {
		"alertMessage": sprintf("wl: %v is in the cluster", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
		}
	}
}

get_wl_connectedto_service(wl) = s {
	service := 	input[_]
	service.kind == "Service"
	wl_connectedto_service(wl, service)
	s = [service]
}

get_wl_connectedto_service(wl) = s {
	services := [service | service = input[_]; service.kind == "Service"]
	count({i | services[i]; wl_connectedto_service(wl, services[i])}) == 0
	s = []
}

wl_connectedto_service(wl, service){
	count({x | service.spec.selector[x] == wl.metadata.labels[x]}) == count(service.spec.selector)
}