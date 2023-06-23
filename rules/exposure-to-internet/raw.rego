package armo_builtins

# Checks if NodePort or LoadBalancer is connected to a workload to expose something
deny[msga] {
    service := input[_]
    service.kind == "Service"
    is_unsafe_service(service)
    
    wl := input[_]
    spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job"}
    spec_template_spec_patterns[wl.kind]
    not wl_connected_to_service(wl, service)
    #result := ["spec.selector.matchLabels"]
    
    msga := {
        "alertMessage": sprintf("workload '%v' is exposed through service '%v'", [wl.metadata.name, service.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "fixPaths": [],
        "failedPaths": [],
        "alertObject": {
            "k8sApiObjects": [wl, service]
        }
    }
}

# Checks if Ingress is connected to a service and a workload to expose something
deny[msga] {
    ingress := input[_]
    ingress.kind == "Ingress"
    
    svc := input[_]
    svc.kind == "Service"
    not is_unsafe_service(svc)

    wl := input[_]
    spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job"}
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
            "k8sApiObjects": [wl, svc, ingress]
        }
    }
} 

# ====================================================================================

is_unsafe_service(svc) {
    svc.spec.type == "NodePort"
}

is_unsafe_service(svc) {
    svc.spec.type == "LoadBalancer"
}

wl_connected_to_service(wl, svc) {
    count({x | svc.spec.selector[x] == wl.metadata.labels[x]}) == count(svc.spec.selector)
}

wl_connected_to_service(wl, svc) {
    wl.spec.selector.matchLabels == svc.spec.selector
}

# check if service is connected to ingress
svc_connected_to_ingress(svc, ingress) {
    rule := ingress.spec.rules[i]
    paths := rule.http.paths[j]
    svc.metadata.name == paths.backend.serviceName
    #result := ["service.metadata.name", sprintf("ingress.spec.rules[%d].http.paths[%d].backend.serviceName", [i,j])]
}

