package armo_builtins


# Check if container has limits
deny[msga] {
  	pods := [pod | pod = input[_]; pod.kind == "Pod"]
    pod := pods[_]
	container := pod.spec.containers[i]
	
	
	begginingOfPath := "spec."
	path := isNoCpuAndMemoryLimitsDefined(container, begginingOfPath, i)
	

	msga := {
		"alertMessage": sprintf("there are no cpu and memory  limits defined for container : %v",  [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
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
	container := wl.spec.template.spec.containers[i]
	
	begginingOfPath	:= "spec.template.spec."
	path := isNoCpuAndMemoryLimitsDefined(container, begginingOfPath, i)
	
	

	msga := {
		"alertMessage": sprintf("there are no cpu and memory limits defined for container : %v",  [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
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
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
	path := isNoCpuAndMemoryLimitsDefined(container, begginingOfPath, i)
	
	msga := {
		"alertMessage": sprintf("there are no cpu and memory limits defined for container : %v",  [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

isNoCpuAndMemoryLimitsDefined(container, begginingOfPath, i) =	path {
	not container.resources.limits
	path := sprintf("%vcontainers[%v].resources", [begginingOfPath, format_int(i, 10)])
}

isNoCpuAndMemoryLimitsDefined(container, begginingOfPath, i) =	path {
	container.resources.limits
	not container.resources.limits.cpu
	path := sprintf("%vcontainers[%v].resources.limits", [begginingOfPath, format_int(i, 10)])
}

isNoCpuAndMemoryLimitsDefined(container, begginingOfPath, i)  =	path {
	container.resources.limits
	not container.resources.limits.memory
	path := sprintf("%vcontainers[%v].resources.limits", [begginingOfPath, format_int(i, 10)])
}
