package armo_builtins
import future.keywords.in


deny[msga] {
    virtualservice := input[_]
    virtualservice.kind == "VirtualService"

    # Get the namescape of the VirtualService
    vs_ns := get_namespace(virtualservice)
    # Looping over the gateways of the VirtualService
    vs_gw_name := virtualservice.spec.gateways[_]
    # Get the namespace of the Gateway
    vs_gw = get_vs_gw_ns(vs_ns, vs_gw_name)

    # Check if the VirtualService is connected to a Gateway
    gateway := input[_]
    gateway.kind == "Gateway"
    gateway.metadata.name == vs_gw.name
    get_namespace(gateway) == vs_gw.namespace

    # print("Found the gateway that the virtualservice is connected to", gateway)

    # Either the gateway is exposed via LoadBalancer service OR has "public" suffix
    gateway_service := is_gateway_public(gateway, input)

    # print("Gateway is public", gateway)

    # Check if the VirtualService is connected to an workload
    # First, find the service that the VirtualService is connected to
    connected_service := input[_]
    connected_service.kind == "Service"
    fqsn := get_fqsn(get_namespace(virtualservice), virtualservice.spec.http[i].route[j].destination.host)
    target_ns := split(fqsn,".")[1]
    target_name := split(fqsn,".")[0]
    # Check if the service is in the same namespace as the VirtualService
    get_namespace(connected_service) == target_ns
    # Check if the service is the target of the VirtualService
    connected_service.metadata.name == target_name

    # print("Found the service that the virtualservice is connected to", connected_service)

    # Check if the service is connected to a workload
    wl := input[_]
    is_same_namespace(connected_service, wl)
    spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
    spec_template_spec_patterns[wl.kind]
    pod := get_pod_spec(wl)["spec"]
    wl_connected_to_service(pod, connected_service)

    # print("Found the workload that the service is connected to", wl)

    failedPaths := [sprintf("spec.http[%d].routes[%d].destination.host", [i,j])]

    # print("Found the failed paths", failedPaths)

    msga := {
        "alertMessage": sprintf("workload '%v' is exposed through virtualservice '%v'", [wl.metadata.name, virtualservice.metadata.name]),
        "packagename": "armo_builtins",
        "failedPaths": [],
        "fixPaths": [],
        "alertScore": 7,
        "alertObject": {
            "k8sApiObjects": [wl]
        },
        "relatedObjects": [
	    {
	            "object": gateway,
	        },
	    {
	            "object": gateway_service,
	        },
	    {
	            "object": virtualservice,
	            "reviewPaths": failedPaths,
	            "failedPaths": failedPaths,
	        },
            {
                    "object": connected_service,
            }
        ]
    }
}

# ====================================================================================

is_gateway_public(gateway, inputs) = svc {
    endswith(gateway.metadata.name, "public")
    inputs[i].kind == "Service"
    inputs[i].metadata.namespace == "istio-system"
    gateway.spec.selector[_] == inputs[i].metadata.labels[_]
    svc := inputs[i]
}

is_gateway_public(gateway, inputs) = svc {
    inputs[i].kind == "Service"
    inputs[i].metadata.namespace == "istio-system"
    gateway.spec.selector[_] == inputs[i].metadata.labels[_]
    is_exposed_service(inputs[i])
    svc := inputs[i]
}

get_namespace(obj) = namespace {
    obj.metadata
    obj.metadata.namespace
    namespace := obj.metadata.namespace
}

get_namespace(obj) = namespace {
    not obj.metadata.namespace
    namespace := "default"
}

get_vs_gw_ns(vs_ns, vs_gw_name) = {"name": name, "namespace": ns} {
    # Check if there is a / in the gateway name
    count(split(vs_gw_name, "/")) == 2
    ns := split(vs_gw_name, "/")[0]
    name := split(vs_gw_name, "/")[1]
}

get_vs_gw_ns(vs_ns, vs_gw_name) = {"name": name, "namespace": ns} {
    # Check if there is no / in the gateway name
    count(split(vs_gw_name, "/")) == 1
    ns := vs_ns
    name := vs_gw_name
}

is_same_namespace(obj1, obj2) {
    obj1.metadata.namespace == obj2.metadata.namespace
}

is_same_namespace(obj1, obj2) {
    not obj1.metadata.namespace
    obj2.metadata.namespace == "default"
}

is_same_namespace(obj1, obj2) {
    not obj2.metadata.namespace
    obj1.metadata.namespace == "default"
}

is_same_namespace(obj1, obj2) {
    not obj1.metadata.namespace
    not obj2.metadata.namespace
}

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

svc_connected_to_virtualservice(svc, virtualservice) = result {
    host := virtualservice.spec.http[i].route[j].destination.host
    svc.metadata.name == host
    result := [sprintf("spec.http[%d].routes[%d].destination.host", [i,j])]
}

get_fqsn(ns, dest_host) = fqsn {
    # verify that this name is without the namespace
    count(split(".", dest_host)) == 1
    fqsn := sprintf("%v.%v.svc.cluster.local", [dest_host, ns])
}

get_fqsn(ns, dest_host) = fqsn {
    count(split(".", dest_host)) == 2
    fqsn := sprintf("%v.svc.cluster.local", [dest_host])
}

get_fqsn(ns, dest_host) = fqsn {
    count(split(".", dest_host)) == 4
    fqsn := dest_host
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
