package armo_builtins
import future.keywords.in


deny[msga] {
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
    wl.metadata.namespace == svc.metadata.namespace
    spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
    spec_template_spec_patterns[wl.kind]
    wl_connected_to_service(wl, svc)

    result := svc_connected_to_httproute(svc, httproute)

    msga := {
        "alertMessage": sprintf("workload '%v' is exposed through httproute '%v'", [wl.metadata.name, httproute.metadata.name]),
        "packagename": "armo_builtins",
        "failedPaths": [],
        "fixPaths": [],
        "alertScore": 7,
        "alertObject": {
            "k8sApiObjects": [wl]
        },
        "relatedObjects": [
		{
	            "object": httproute,
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

svc_connected_to_httproute(svc, httproute) = result {
    rule := httproute.spec.rules[i]
    ref := rule.backendRefs[j]
    ref.kind == "Service"
    svc.metadata.name == ref.name
    result := [sprintf("spec.rules[%d].backendRefs[%d].name", [i,j])]
}

