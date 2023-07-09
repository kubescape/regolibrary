package armo_builtins

# Fails if pod does not have container with CPU-limit or request
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	not request_or_limit_cpu(container)

	fixPaths := [{"path": sprintf("spec.containers[%v].resources.limits.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"},
				{"path": sprintf("spec.containers[%v].resources.requests.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v does not have CPU-limit or request", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not have container with CPU-limit or request
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
    not request_or_limit_cpu(container)

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].resources.limits.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"},
				{"path": sprintf("spec.template.spec.containers[%v].resources.requests.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob does not have container with CPU-limit or request
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    not request_or_limit_cpu(container)

	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].resources.limits.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"},
				{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].resources.requests.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}




###################################################################################################################

# Fails if pod exceeds CPU-limit or request
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	request_or_limit_cpu(container)
	resource := is_min_max_exceeded_cpu(container)
	resource != ""

	failed_paths := sprintf("spec.containers[%v].%v", [format_int(i, 10), resource])

	msga := {
		"alertMessage": sprintf("Container: %v exceeds CPU-limit or request", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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

	request_or_limit_cpu(container)
	resource := is_min_max_exceeded_cpu(container)
	resource != ""

	failed_paths := sprintf("spec.template.spec.containers[%v].%v", [format_int(i, 10), resource])

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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

	request_or_limit_cpu(container)
   	resource := is_min_max_exceeded_cpu(container)
	resource != ""

	failed_paths := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].%v", [format_int(i, 10), resource])

    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}




#################################################################################################################3

request_or_limit_cpu(container) {
	container.resources.limits.cpu
	container.resources.requests.cpu
}


is_min_max_exceeded_cpu(container)  = "resources.limits.cpu" {
	cpu_limit := container.resources.limits.cpu
	is_limit_exceeded_cpu(cpu_limit)
} else = "resouces.requests.cpu" {
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

# Compare according to unit - max
compare_max(max, given) {
	endswith(max, "Mi")
	endswith(given, "Mi")
	split_max :=  split(max, "Mi")[0]
	split_given :=  split(given, "Mi")[0]
	split_given > split_max
}

compare_max(max, given) {
	endswith(max, "M")
	endswith(given, "M")
	split_max :=  split(max, "M")[0]
	split_given :=  split(given, "M")[0]
	split_given > split_max
}

compare_max(max, given) {
	endswith(max, "m")
	endswith(given, "m")
	split_max :=  split(max, "m")[0]
	split_given :=  split(given, "m")[0]
	split_given > split_max
}

compare_max(max, given) {
	not is_special_measure(max)
	not is_special_measure(given)
	given > max
}



################
# Compare according to unit - min
compare_min(min, given) {
	endswith(min, "Mi")
	endswith(given, "Mi")
	split_min :=  split(min, "Mi")[0]
	split_given :=  split(given, "Mi")[0]
	split_given < split_min
}

compare_min(min, given) {
	endswith(min, "M")
	endswith(given, "M")
	split_min :=  split(min, "M")[0]
	split_given :=  split(given, "M")[0]
	split_given < split_min
}

compare_min(min, given) {
	endswith(min, "m")
	endswith(given, "m")
	split_min :=  split(min, "m")[0]
	split_given :=  split(given, "m")[0]
	split_given < split_min
}

compare_min(min, given) {
	not is_special_measure(min)
	not is_special_measure(given)
	given < min
}


# Check that is same unit
is_special_measure(unit) {
	endswith(unit, "m")
}

is_special_measure(unit) {
	endswith(unit, "M")
}

is_special_measure(unit) {
	endswith(unit, "Mi")
}
