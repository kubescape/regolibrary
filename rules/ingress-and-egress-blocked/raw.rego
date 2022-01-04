package armo_builtins


# For pods
deny[msga] {
 		pods := [pod |  pod= input[_]; pod.kind == "Pod"]
		networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
		pod := pods[_]
		networkpoliciesConnectedToPod := [networkpolicie |  networkpolicie= networkpolicies[_];  podConnectedToNetworkPolicy(pod, networkpolicie)]
		count(networkpoliciesConnectedToPod) > 0
        goodPolicies := [goodpolicie |  goodpolicie= networkpoliciesConnectedToPod[_];  isIngerssEgressPolicy(goodpolicie)]
		count(goodPolicies) < 1

    msga := {
		"alertMessage": sprintf("Pod: %v does not have ingress/egress defined", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
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
		networkpoliciesConnectedToPod := [networkpolicie |  networkpolicie= networkpolicies[_];  podConnectedToNetworkPolicy(pod, networkpolicie)]
		count(networkpoliciesConnectedToPod) < 1

    msga := {
		"alertMessage": sprintf("Pod: %v does not have ingress/egress defined", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
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
	networkpoliciesConnectedToPod := [networkpolicie |  networkpolicie= networkpolicies[_];  wlConnectedToNetworkPolicy(wl, networkpolicie)]
	count(networkpoliciesConnectedToPod) > 0
    goodPolicies := [goodpolicie |  goodpolicie= networkpoliciesConnectedToPod[_];  isIngerssEgressPolicy(goodpolicie)]
	count(goodPolicies) < 1

    msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
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
	networkpoliciesConnectedToPod := [networkpolicie |  networkpolicie= networkpolicies[_];  wlConnectedToNetworkPolicy(wl, networkpolicie)]
	count(networkpoliciesConnectedToPod) < 1

    msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
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
	networkpoliciesConnectedToPod := [networkpolicie |  networkpolicie= networkpolicies[_];  cronjobConnectedToNetworkPolicy(wl, networkpolicie)]
	count(networkpoliciesConnectedToPod) > 0
    goodPolicies := [goodpolicie |  goodpolicie= networkpoliciesConnectedToPod[_];  isIngerssEgressPolicy(goodpolicie)]
	count(goodPolicies) < 1

    msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
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
	networkpoliciesConnectedToPod := [networkpolicie |  networkpolicie= networkpolicies[_];  cronjobConnectedToNetworkPolicy(wl, networkpolicie)]
	count(networkpoliciesConnectedToPod) < 1

    msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


podConnectedToNetworkPolicy(pod, networkpolicie){
	networkpolicie.metadata.namespace == pod.metadata.namespace
    count(networkpolicie.spec.podSelector) > 0
    count({x | networkpolicie.spec.podSelector.matchLabels[x] == pod.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

podConnectedToNetworkPolicy(pod, networkpolicie){
	networkpolicie.metadata.namespace == pod.metadata.namespace
    count(networkpolicie.spec.podSelector) == 0
}

wlConnectedToNetworkPolicy(wl, networkpolicie){
	wl.metadata.namespace == networkpolicie.metadata.namespace
    count(networkpolicie.spec.podSelector) == 0
}


wlConnectedToNetworkPolicy(wl, networkpolicie){
	wl.metadata.namespace == networkpolicie.metadata.namespace
	count(networkpolicie.spec.podSelector) > 0
    count({x | networkpolicie.spec.podSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}


cronjobConnectedToNetworkPolicy(cj, networkpolicie){
	cj.metadata.namespace == networkpolicie.metadata.namespace
    count(networkpolicie.spec.podSelector) == 0
}

cronjobConnectedToNetworkPolicy(cj, networkpolicie){
	cj.metadata.namespace == networkpolicie.metadata.namespace
	count(networkpolicie.spec.podSelector) > 0
    count({x | networkpolicie.spec.podSelector.matchLabels[x] == cj.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

isIngerssEgressPolicy(networkpolicie) {
    list_contains(networkpolicie.spec.policyTypes, "Ingress")
    list_contains(networkpolicie.spec.policyTypes, "Egress")
 }

list_contains(list, element) {
  some i
  list[i] == element
}