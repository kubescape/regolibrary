package armo_builtins

# Checks if NodePort or LoadBalancer is connected to a workload to expose something
deny[msga] {
    service := input[_]
    service.kind == "Service"
    is_exposed_service(service)

    wl := input[_]
    spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
    spec_template_spec_patterns[wl.kind]
    is_same_namespace(wl.metadata, service.metadata)
    pod := get_pod_spec(wl)["spec"]
    wl_connected_to_service(pod, service)
    failPath := ["spec.type"]
    msga := {
        "alertMessage": sprintf("workload '%v' is exposed through service '%v'", [wl.metadata.name, service.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "fixPaths": [],
        "failedPaths": [],
        "alertObject": {
            "k8sApiObjects": [wl]
        },
        "relatedObjects": [{
            "object": service,
		    "reviewPaths": failPath,
            "failedPaths": failPath,
        }]
    }
}

# Checks if Ingress is connected to a service and a workload to expose something
deny[msga] {
    ingress := input[_]
    ingress.kind == "Ingress"

    svc := input[_]
    svc.kind == "Service"

    # Make sure that they belong to the same namespace
    svc.metadata.namespace == ingress.metadata.namespace

    # avoid duplicate alerts
    # if service is already exposed through NodePort or LoadBalancer workload will fail on that
    not is_exposed_service(svc)

    wl := input[_]
    spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
    spec_template_spec_patterns[wl.kind]
    is_same_namespace(wl.metadata, svc.metadata)
    wl_connected_to_service(wl, svc)

    result := svc_connected_to_ingress(svc, ingress)

    msga := {
        "alertMessage": sprintf("workload '%v' is exposed through ingress '%v'", [wl.metadata.name, ingress.metadata.name]),
        "packagename": "armo_builtins",
        "failedPaths": [],
        "fixPaths": [],
        "alertScore": 7,
        "alertObject": {
            "k8sApiObjects": [wl]
        },
        "relatedObjects": [
		{
	            "object": ingress,
		    "reviewPaths": result,
	            "failedPaths": result,
	        },
		{
	            "object": svc,
		}
        ]
    }
}

# ====================================================================================

is_exposed_service(svc) {
    svc.spec.type == "NodePort"
}

is_exposed_service(svc) {
    svc.spec.type == "LoadBalancer"
}


wl_connected_to_service(wl, svc) {
    count({x | svc.spec.selector[x] == wl.metadata.labels[x]}) == count(svc.spec.selector)
}

wl_connected_to_service(wl, svc) {
    wl.spec.selector.matchLabels == svc.spec.selector
}

wl_connected_to_service(wl, svc) {
    count({x | svc.spec.selector[x] == wl.spec.template.metadata.labels[x]}) == count(svc.spec.selector)
}

# check if service is connected to ingress
svc_connected_to_ingress(svc, ingress) = result {
    rule := ingress.spec.rules[i]
    paths := rule.http.paths[j]
    svc.metadata.name == paths.backend.service.name
    result := [sprintf("spec.rules[%d].http.paths[%d].backend.service.name", [i,j])]
}



is_same_namespace(metadata1, metadata2) {
	metadata1.namespace == metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
	not metadata1.namespace
	not metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
	not metadata2.namespace
	metadata1.namespace == "default"
}

is_same_namespace(metadata1, metadata2) {
	not metadata1.namespace
	metadata2.namespace == "default"
}



# get_volume - get resource spec paths for {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_pod_spec(resources) := result {
	resources_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	resources_kinds[resources.kind]
	result = {"spec": resources.spec.template, "start_of_path": "spec.template."}
}

# get_volume - get resource spec paths for "Pod"
get_pod_spec(resources) := result {
	resources.kind == "Pod"
	result = {"spec": resources, "start_of_path": ""}
}

# get_volume - get resource spec paths for "CronJob"
get_pod_spec(resources) := result {
	resources.kind == "CronJob"
	result = {"spec": resources.spec.jobTemplate.spec.template.spec, "start_of_path": "spec.jobTemplate.spec.template.spec."}
}
