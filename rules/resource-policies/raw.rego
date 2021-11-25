package armo_builtins


# Check if container has limits
deny[msga] {
  	pods := [pod | pod = input[_]; pod.kind == "Pod"]
    pod := pods[_]
	container := pod.spec.containers[_]
	not  container.resources.limits

	msga := {
		"alertMessage": sprintf("there are no resource limits defined for container : %v",  [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}


# Check if container has limits - for workloads
# If there is no limits specified in the workload, we check the namespace, since if limits are only specified for namespace
# and not in workload, it won't be on the yaml
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[_]
	not  container.resources.limits
	isNamespaceWithLimits(wl.metadata.namespace)

	msga := {
		"alertMessage": sprintf("there are no resource limits defined for container : %v",  [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
	
}

# Check if container has limits - for cronjobs
# If there is no limits specified in the cronjob, we check the namespace, since if limits are only specified for namespace
# and not in cronjob, it won't be on the yaml
deny [msga] {
    wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[_]
	not  container.resources.limits
	isNamespaceWithLimits(wl.metadata.namespace)
	msga := {
		"alertMessage": sprintf("there are no resource limits defined for container : %v",  [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if LimitRange exists but it does not define maximum usage of resources
deny[msga] {

    limitRanges := [limitRange | limitRange = input[_]; limitRange.kind == "LimitRange"]
    limitRange := limitRanges[_]

	limits := limitRange.spec.limits[_]
    not limits.max

	msga := {
		"alertMessage": sprintf("the following LimitRange: %v does not define a maximum field for resources",  [limitRange.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [limitRange]
		}
	}
}

# Fails if ResourQuota exists but it does not define maximum usage of resources
deny[msga] {
    resourceQuotas := [resourceQuota | resourceQuota = input[_]; resourceQuota.kind == "ResourceQuota"]
    resourceQuota := resourceQuotas[_]

    not resourceQuota.spec.hard

	msga := {
		"alertMessage": sprintf("the following ResourQuota: %v does not define a hard field",  [resourceQuota.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [resourceQuota]
		}
	}
}


list_contains(list, element) {
  some i
  list[i] == element
}


# Check only LimitRange. For ResourceQuota limits need to be specified. 
isNamespaceWithLimits(namespace) {
    limitRanges := [policy.metadata.namespace | policy = input[_]; policy.kind == "LimitRange"]
    not list_contains(limitRanges, namespace)
}
