package armo_builtins

# Checks if NodePort or LoadBalancer is connected to a workload to expose something
deny[msga] {
    service := input[_]
    service.kind == "Service"
    is_exposed_service(service)

    wl := input[_]
    spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
    spec_template_spec_patterns[wl.kind]
    wl_connected_to_service(wl, service)
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


