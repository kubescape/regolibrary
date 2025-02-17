package armo_builtins


# For pods
deny[msga] {
	pods := [pod |  pod= input[_]; pod.kind == "Pod"]
	networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
	pod := pods[_]
	network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  pod_connected_to_network_policy(pod, networkpolicie)]
	count(network_policies_connected_to_pod) > 0
	goodPolicies := [goodpolicie |  goodpolicie= network_policies_connected_to_pod[_];  is_ingerss_egress_policy(goodpolicie)]
	count(goodPolicies) < 1

    msga := {
		"alertMessage": sprintf("Pod: %v does not have ingress/egress defined", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}

}

# For pods
deny[msga] {
 		pods := [pod |  pod= input[_]; pod.kind == "Pod"]
		networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
		pod := pods[_]
		network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  pod_connected_to_network_policy(pod, networkpolicie)]
		count(network_policies_connected_to_pod) < 1

    msga := {
		"alertMessage": sprintf("Pod: %v does not have ingress/egress defined", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}

}

# For workloads
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
	network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  wlConnectedToNetworkPolicy(wl, networkpolicie)]
	count(network_policies_connected_to_pod) > 0
    goodPolicies := [goodpolicie |  goodpolicie= network_policies_connected_to_pod[_];  is_ingerss_egress_policy(goodpolicie)]
	count(goodPolicies) < 1

    msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# For workloads
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
	network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  wlConnectedToNetworkPolicy(wl, networkpolicie)]
	count(network_policies_connected_to_pod) < 1

    msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# For Cronjobs
deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
    networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
	network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  cronjob_connected_to_network_policy(wl, networkpolicie)]
	count(network_policies_connected_to_pod) > 0
    goodPolicies := [goodpolicie |  goodpolicie= network_policies_connected_to_pod[_];  is_ingerss_egress_policy(goodpolicie)]
	count(goodPolicies) < 1

    msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# For Cronjobs
deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
    networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
	network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  cronjob_connected_to_network_policy(wl, networkpolicie)]
	count(network_policies_connected_to_pod) < 1

    msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
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

pod_connected_to_network_policy(pod, networkpolicie){
	is_same_namespace(networkpolicie.metadata, pod.metadata)
    count(networkpolicie.spec.podSelector) > 0
    count({x | networkpolicie.spec.podSelector.matchLabels[x] == pod.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

pod_connected_to_network_policy(pod, networkpolicie){
	is_same_namespace(networkpolicie.metadata ,pod.metadata)
    count(networkpolicie.spec.podSelector) == 0
}

wlConnectedToNetworkPolicy(wl, networkpolicie){
	is_same_namespace(wl.metadata , networkpolicie.metadata)
    count(networkpolicie.spec.podSelector) == 0
}


wlConnectedToNetworkPolicy(wl, networkpolicie){
	is_same_namespace(wl.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.podSelector) > 0
    count({x | networkpolicie.spec.podSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}


cronjob_connected_to_network_policy(cj, networkpolicie){
	is_same_namespace(cj.metadata , networkpolicie.metadata)
    count(networkpolicie.spec.podSelector) == 0
}

cronjob_connected_to_network_policy(cj, networkpolicie){
	is_same_namespace(cj.metadata , networkpolicie.metadata)
	count(networkpolicie.spec.podSelector) > 0
    count({x | networkpolicie.spec.podSelector.matchLabels[x] == cj.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

is_ingerss_egress_policy(networkpolicie) {
    list_contains(networkpolicie.spec.policyTypes, "Ingress")
}

is_ingerss_egress_policy(networkpolicie) {
    list_contains(networkpolicie.spec.policyTypes, "Egress")
}

list_contains(list, element) {
  some i
  list[i] == element
}