package armo_builtins

import future.keywords.in

deny[msga] {
	service := input[_]
	service.kind == "Service"
	service_type := object.get(service.spec, "type", "ClusterIP")
	service_type != "ExternalName"

	selector := object.get(service.spec, "selector", {})
	count(selector) > 0

	not has_matching_workload(service, input)

	msga := {
		"alertMessage": sprintf("Service '%v' selector matches no workloads in namespace '%v'", [service.metadata.name, service_namespace(service)]),
		"packagename": "armo_builtins",
		"failedPaths": ["spec.selector"],
		"fixPaths": [],
		"alertScore": 3,
		"alertObject": {
			"k8sApiObjects": [service],
		},
	}
}

has_matching_workload(service, all) {
	wl := all[_]
	is_workload(wl)
	same_namespace(service, wl)
	labels_match(service.spec.selector, pod_template_labels(wl))
}

is_workload(wl) {
	workload_kinds := {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob", "ReplicationController"}
	workload_kinds[wl.kind]
}

pod_template_labels(wl) = labels {
	wl.kind == "Pod"
	labels := object.get(wl.metadata, "labels", {})
}

pod_template_labels(wl) = labels {
	controller_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}
	controller_kinds[wl.kind]
	labels := object.get(wl.spec.template.metadata, "labels", {})
}

pod_template_labels(wl) = labels {
	wl.kind == "CronJob"
	labels := object.get(wl.spec.jobTemplate.spec.template.metadata, "labels", {})
}

labels_match(selector, labels) {
	count(selector) > 0
	not selector_mismatch(selector, labels)
}

selector_mismatch(selector, labels) {
	selector[k]
	not labels[k] == selector[k]
}

same_namespace(a, b) {
	service_namespace(a) == workload_namespace(b)
}

service_namespace(svc) = ns {
	ns := object.get(svc.metadata, "namespace", "default")
}

workload_namespace(wl) = ns {
	ns := object.get(wl.metadata, "namespace", "default")
}
