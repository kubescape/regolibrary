package armo_builtins

import rego.v1

deny contains msga if {
	httproute := input[_]
	httproute.kind in ["HTTPRoute", "TCPRoute", "UDPRoute"]

	svc := input[_]
	svc.kind == "Service"

	# Make sure that they belong to the same namespace
	svc.metadata.namespace == httproute.metadata.namespace

	# avoid duplicate alerts
	# if service is already exposed through NodePort or LoadBalancer workload will fail on that
	not is_exposed_service(svc)

	wl := input[_]
	is_same_namespace(wl.metadata, svc.metadata)
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
	spec_template_spec_patterns[wl.kind]
	pod := get_pod_spec(wl).spec
	wl_connected_to_service(pod, svc)

	result := svc_connected_to_httproute(svc, httproute)

	msga := {
		"alertMessage": sprintf("workload '%v' is exposed through httproute '%v'", [wl.metadata.name, httproute.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertScore": 7,
		"alertObject": {"k8sApiObjects": [wl]},
		"relatedObjects": [
			{
				"object": httproute,
				"reviewPaths": result,
				"failedPaths": result,
			},
			{"object": svc},
		],
	}
}

# ====================================================================================

is_exposed_service(svc) if {
	svc.spec.type == "NodePort"
}

is_exposed_service(svc) if {
	svc.spec.type == "LoadBalancer"
}

wl_connected_to_service(wl, svc) if {
	count({x | svc.spec.selector[x] == wl.metadata.labels[x]}) == count(svc.spec.selector)
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

# get_volume - get resource spec paths for {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_pod_spec(resources) := result if {
	resources_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	resources_kinds[resources.kind]
	result = {"spec": resources.spec.template, "start_of_path": "spec.template."}
}

# get_volume - get resource spec paths for "Pod"
get_pod_spec(resources) := result if {
	resources.kind == "Pod"
	result = {"spec": resources, "start_of_path": ""}
}

# get_volume - get resource spec paths for "CronJob"
get_pod_spec(resources) := result if {
	resources.kind == "CronJob"
	result = {"spec": resources.spec.jobTemplate.spec.template.spec, "start_of_path": "spec.jobTemplate.spec.template.spec."}
}

svc_connected_to_httproute(svc, httproute) := result if {
	rule := httproute.spec.rules[i]
	ref := rule.backendRefs[j]
	ref.kind == "Service"
	svc.metadata.name == ref.name
	result := [sprintf("spec.rules[%d].backendRefs[%d].name", [i, j])]
}
