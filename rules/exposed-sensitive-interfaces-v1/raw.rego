# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

import data.kubernetes.api.client

# loadbalancer
deny contains msga if {
	wl_names := data.postureControlInputs.sensitiveInterfaces
	wl := input[_]
	workload_types = {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "Pod", "CronJob"}
	workload_types[wl.kind]

	# see default-config-inputs.json for list values
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	service := input[_]
	service.kind == "Service"
	service.spec.type == "LoadBalancer"

	load_balancer_provisioned(service)

	wlvector = {
		"name": wl.metadata.name,
		"namespace": wl.metadata.namespace,
		"kind": wl.kind,
		"relatedObjects": [service],
	}

	result := wl_connectedto_service(wl, service)

	msga := {
		"alertMessage": sprintf("service: %v is exposed", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": result,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector,
		},
	}
}

# nodePort
# get a pod connected to that service, get nodeIP (hostIP?)
# use ip + nodeport
deny contains msga if {
	wl_names := data.postureControlInputs.sensitiveInterfaces
	wl := input[_]
	wl.kind == "Pod"

	# see default-config-inputs.json for list values
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	service := input[_]
	service.kind == "Service"
	service.spec.type == "NodePort"

	wlvector = {
		"name": wl.metadata.name,
		"namespace": wl.metadata.namespace,
		"kind": wl.kind,
		"relatedObjects": [service],
	}

	result := wl_connectedto_service(wl, service)

	msga := {
		"alertMessage": sprintf("service: %v is exposed", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": result,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector,
		},
	}
}

# nodePort
# get a workload connected to that service, get nodeIP (hostIP?)
# use ip + nodeport
deny contains msga if {
	wl_names := data.postureControlInputs.sensitiveInterfaces
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}
	wl := input[_]
	spec_template_spec_patterns[wl.kind]

	# see default-config-inputs.json for list values
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	service := input[_]
	service.kind == "Service"
	service.spec.type == "NodePort"

	wlvector = {
		"name": wl.metadata.name,
		"namespace": wl.metadata.namespace,
		"kind": wl.kind,
		"relatedObjects": [service],
	}

	result := wl_connectedto_service(wl, service)

	msga := {
		"alertMessage": sprintf("service: %v is exposed", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": result,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector,
		},
	}
}

# ====================================================================================

# The cloud provider records the load balancer's address in status: an IP-based
# load balancer sets ip, a DNS-based one (for example AWS ELB/NLB) sets only hostname.
load_balancer_provisioned(service) if {
	service.status.loadBalancer.ingress[_].ip
}

load_balancer_provisioned(service) if {
	service.status.loadBalancer.ingress[_].hostname
}

wl_connectedto_service(wl, service) := paths if {
	wl.metadata.namespace == service.metadata.namespace
	count(service.spec.selector) > 0
	count({x | service.spec.selector[x] == wl.metadata.labels[x]}) == count(service.spec.selector)
	paths = ["spec.selector.matchLabels", "spec.selector"]
}

wl_connectedto_service(wl, service) := paths if {
	wl.metadata.namespace == service.metadata.namespace
	count(service.spec.selector) > 0
	wl.spec.selector.matchLabels == service.spec.selector
	paths = ["spec.selector.matchLabels", "spec.selector"]
}

# A Service selects the pods a workload creates, and those carry the pod template's labels
wl_connectedto_service(wl, service) := paths if {
	wl.metadata.namespace == service.metadata.namespace
	count(service.spec.selector) > 0
	template_labels := pod_template_labels(wl)
	count({x | service.spec.selector[x] == template_labels[x]}) == count(service.spec.selector)
	paths := ["spec.selector.matchLabels", "spec.selector"]
}

pod_template_labels(wl) := wl.spec.template.metadata.labels if {
	wl.kind != "CronJob"
}

pod_template_labels(wl) := wl.spec.jobTemplate.spec.template.metadata.labels if {
	wl.kind == "CronJob"
}
