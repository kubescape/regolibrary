package armo_builtins


# Check if container has limits
deny[msga] {
  	pods := [pod | pod = input[_]; pod.kind == "Pod"]
    pod := pods[_]
	container := pod.spec.containers[i]
	
	
	beggining_of_path := "spec."
	fixPath := is_no_cpu_and_memory_limits_defined(container, beggining_of_path, i)
	

	msga := {
		"alertMessage": sprintf("there are no cpu and memory  limits defined for container : %v",  [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPath,
		"failedPaths": [],
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
	
	beggining_of_path	:= "spec.template.spec."
	fixPath := is_no_cpu_and_memory_limits_defined(container, beggining_of_path, i)
	
	

	msga := {
		"alertMessage": sprintf("there are no cpu and memory limits defined for container : %v",  [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPath,
		"failedPaths": [],
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
	
	beggining_of_path := "spec.jobTemplate.spec.template.spec."
	fixPath := is_no_cpu_and_memory_limits_defined(container, beggining_of_path, i)
	
	msga := {
		"alertMessage": sprintf("there are no cpu and memory limits defined for container : %v",  [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPath,
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# no limits at all
is_no_cpu_and_memory_limits_defined(container, beggining_of_path, i) =  fixPath {
	not container.resources.limits
	fixPath = [{"path": sprintf("%vcontainers[%v].resources.limits.cpu", [beggining_of_path, format_int(i, 10)]), "value":"YOUR_VALUE"}, {"path": sprintf("%vcontainers[%v].resources.limits.memory", [beggining_of_path, format_int(i, 10)]), "value":"YOUR_VALUE"}]
}

# only memory limit
is_no_cpu_and_memory_limits_defined(container, beggining_of_path, i) = fixPath {
	container.resources.limits
	not container.resources.limits.cpu
	container.resources.limits.memory
	fixPath = [{"path": sprintf("%vcontainers[%v].resources.limits.cpu", [beggining_of_path, format_int(i, 10)]), "value":"YOUR_VALUE"}]
}

# only cpu limit
is_no_cpu_and_memory_limits_defined(container, beggining_of_path, i) =fixPath {
	container.resources.limits
	not container.resources.limits.memory
	container.resources.limits.cpu
	fixPath = [{"path": sprintf("%vcontainers[%v].resources.limits.memory", [beggining_of_path, format_int(i, 10)]), "value":"YOUR_VALUE"}]
	failed_path = ""
}
# limits but without capu and memory 
is_no_cpu_and_memory_limits_defined(container, beggining_of_path, i) = fixPath {
	container.resources.limits
	not container.resources.limits.memory
	not container.resources.limits.cpu
	fixPath = [{"path": sprintf("%vcontainers[%v].resources.limits.cpu", [beggining_of_path, format_int(i, 10)]), "value":"YOUR_VALUE"}, {"path": sprintf("%vcontainers[%v].resources.limits.memory", [beggining_of_path, format_int(i, 10)]), "value":"YOUR_VALUE"}]
}