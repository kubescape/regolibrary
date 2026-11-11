# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# input: pod
# apiversion: v1
# does:	returns the external facing services of that pod

deny contains msga if {
	path := "metadata.labels"
	pod := input[_]
	pod.kind == "Pod"
	podns := obj_namespace(pod)
	podname := pod.metadata.name
	labels := pod.metadata.labels
	service := input[_]
	service.kind == "Service"
	obj_namespace(service) == podns
	selector_matches(service.spec.selector, labels)

	wlvector = {
		"name": pod.metadata.name,
		"namespace": podns,
		"kind": pod.kind,
		"relatedObjects": service,
	}
	msga := {
		"alertMessage": sprintf("pod %v/%v exposed by SSH services: %v", [podns, podname, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector,
		},
	}
}

deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	path := "spec.template.metadata.labels"

	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	labels := wl.spec.template.metadata.labels
	service := input[_]
	service.kind == "Service"
	obj_namespace(service) == obj_namespace(wl)
	selector_matches(service.spec.selector, labels)

	wlvector = {
		"name": wl.metadata.name,
		"namespace": obj_namespace(wl),
		"kind": wl.kind,
		"relatedObjects": service,
	}

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector,
		},
	}
}

deny contains msga if {
	path := "spec.jobTemplate.spec.template.metadata.labels"
	wl := input[_]
	wl.kind == "CronJob"
	labels := wl.spec.jobTemplate.spec.template.metadata.labels
	service := input[_]
	service.kind == "Service"
	obj_namespace(service) == obj_namespace(wl)
	selector_matches(service.spec.selector, labels)

	wlvector = {
		"name": wl.metadata.name,
		"namespace": obj_namespace(wl),
		"kind": wl.kind,
		"relatedObjects": service,
	}

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector,
		},
	}
}

# A manifest without metadata.namespace is created in the namespace it is
# applied to, so two such manifests applied together share it; like a
# cluster that defaults it, treat a missing namespace as "default".
obj_namespace(obj) := object.get(obj.metadata, "namespace", "default")

# A Service selects every pod whose labels contain all of the selector's
# key/value pairs; the pod may carry other labels too.
selector_matches(selector, labels) if {
	count(selector) > 0
	every key, value in selector {
		labels[key] == value
	}
}
