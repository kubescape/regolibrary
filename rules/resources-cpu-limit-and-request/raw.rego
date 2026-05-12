package armo_builtins

# ==================================== no CPU requests =============================================
# Fails if pod does not have container with CPU request
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	not container.resources.requests.cpu

	fixPaths := [{"path": sprintf("spec.containers[%v].resources.requests.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v does not have CPU-limit or request", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not have container with CPU requests
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
    not container.resources.requests.cpu

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].resources.requests.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob does not have container with CPU requests
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    not container.resources.requests.cpu

	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].resources.requests.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# ==================================== no CPU limits =============================================
# Fails if pod does not have container with CPU-limits
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	not container.resources.limits.cpu

	fixPaths := [{"path": sprintf("spec.containers[%v].resources.limits.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v does not have CPU-limit or request", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not have container with CPU-limits
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
    not container.resources.limits.cpu

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].resources.limits.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob does not have container with CPU-limits
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    not container.resources.limits.cpu

	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].resources.limits.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



# ============================================= cpu limits exceed min/max =============================================

# Fails if pod exceeds CPU-limit or request
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	path := "resources.limits.cpu" 
	cpu_limit := container.resources.limits.cpu
	is_limit_exceeded_cpu(cpu_limit)

	failed_paths := sprintf("spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v exceeds CPU-limit or request", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload exceeds CPU-limit or request
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]

	path := "resources.limits.cpu" 
	cpu_limit := container.resources.limits.cpu
	is_limit_exceeded_cpu(cpu_limit)

	failed_paths := sprintf("spec.template.spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob doas exceeds CPU-limit or request
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]

   	path := "resources.limits.cpu" 
	cpu_limit := container.resources.limits.cpu
	is_limit_exceeded_cpu(cpu_limit)

	failed_paths := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].%v", [format_int(i, 10), path])

    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# ============================================= cpu requests exceed min/max =============================================

# Fails if pod exceeds CPU-limit or request
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	path := "resources.requests.cpu" 
	cpu_req := container.resources.requests.cpu
	is_req_exceeded_cpu(cpu_req)

	failed_paths := sprintf("spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v exceeds CPU-limit or request", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload exceeds CPU-limit or request
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]

	path := "resources.requests.cpu" 
	cpu_req := container.resources.requests.cpu
	is_req_exceeded_cpu(cpu_req)

	failed_paths := sprintf("spec.template.spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob doas exceeds CPU-limit or request
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]

	path := "resources.requests.cpu" 
	cpu_req := container.resources.requests.cpu
	is_req_exceeded_cpu(cpu_req)

	failed_paths := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].%v", [format_int(i, 10), path])

    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


#################################################################################################################


is_min_max_exceeded_cpu(container)  = "resources.limits.cpu" {
	cpu_limit := container.resources.limits.cpu
	is_limit_exceeded_cpu(cpu_limit)
} else = "resources.requests.cpu" {
	cpu_req := container.resources.requests.cpu
	is_req_exceeded_cpu(cpu_req)
} else = ""


is_limit_exceeded_cpu(cpu_limit) {
	is_min_limit_exceeded_cpu(cpu_limit)
}

is_limit_exceeded_cpu(cpu_limit) {
	is_max_limit_exceeded_cpu(cpu_limit)
}

is_req_exceeded_cpu(cpu_req) {
	is_max_request_exceeded_cpu(cpu_req)
}

is_req_exceeded_cpu(cpu_req) {
	is_min_request_exceeded_cpu(cpu_req)
}

is_max_limit_exceeded_cpu(cpu_limit) {
	cpu_limit_max :=  data.postureControlInputs.cpu_limit_max[_]
	compare_max(cpu_limit_max, cpu_limit)
}

is_min_limit_exceeded_cpu(cpu_limit) {
	cpu_limit_min :=  data.postureControlInputs.cpu_limit_min[_]
	compare_min(cpu_limit_min, cpu_limit)
}

is_max_request_exceeded_cpu(cpu_req) {
	cpu_req_max :=  data.postureControlInputs.cpu_request_max[_]
	compare_max(cpu_req_max, cpu_req)
}

is_min_request_exceeded_cpu(cpu_req) {
	cpu_req_min := data.postureControlInputs.cpu_request_min[_]
	compare_min(cpu_req_min, cpu_req)
}

##############
# helpers

# Compare two Kubernetes CPU quantities by normalizing both sides to millicores.
# Supports the milli suffix ("m") and unitless whole/fractional cores.
compare_max(max, given) {
	cpu_to_millicores(given) > cpu_to_millicores(max)
}

compare_min(min, given) {
	cpu_to_millicores(given) < cpu_to_millicores(min)
}

# Parse a Kubernetes CPU quantity string into millicores.
# "500m" -> 500, "1" -> 1000, "0.5" -> 500.
cpu_to_millicores(q) = n {
	s := sprintf("%v", [q])
	endswith(s, "m")
	n := to_number(trim_suffix(s, "m"))
} else = n {
	n := to_number(q) * 1000
}
