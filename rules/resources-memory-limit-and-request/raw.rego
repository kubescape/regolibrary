package armo_builtins

#  ================================== no memory limits ==================================
# Fails if pod does not have container with memory-limits
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	not container.resources.limits.memory
	fixPaths := [{"path": sprintf("spec.containers[%v].resources.limits.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v does not have memory-limit or request", [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload does not have container with memory-limits
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	not container.resources.limits.memory
	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].resources.limits.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have memory-limit or request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob does not have container with memory-limits
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	not container.resources.limits.memory
	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].resources.limits.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have memory-limit or request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

#  ================================== no memory requests ==================================
# Fails if pod does not have container with memory requests
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	not container.resources.requests.memory
	fixPaths := [{"path": sprintf("spec.containers[%v].resources.requests.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v does not have memory-limit or request", [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload does not have container with memory requests
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	not container.resources.requests.memory
	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].resources.requests.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have memory-limit or request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob does not have container with memory requests
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	not container.resources.requests.memory
	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].resources.requests.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have memory-limit or request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}


# ============================================= memory requests exceed min/max =============================================

# Fails if pod exceeds memory request
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	memory_req := container.resources.requests.memory
	is_req_exceeded_memory(memory_req)
	path := "resources.requests.memory"

	failed_paths := sprintf("spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v exceeds memory request", [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload exceeds memory request
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]

	memory_req := container.resources.requests.memory
	is_req_exceeded_memory(memory_req)
	path := "resources.requests.memory"

	failed_paths := sprintf("spec.template.spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds memory request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob exceeds memory request
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]

	memory_req := container.resources.requests.memory
	is_req_exceeded_memory(memory_req)
	path := "resources.requests.memory" 

	failed_paths := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds memory request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# ============================================= memory limits exceed min/max =============================================

# Fails if pod exceeds memory-limit 
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	memory_limit := container.resources.limits.memory
	is_limit_exceeded_memory(memory_limit)
	path := "resources.limits.memory"

	failed_paths := sprintf("spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v exceeds memory-limit ", [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload exceeds memory-limit 
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]

	memory_limit := container.resources.limits.memory
	is_limit_exceeded_memory(memory_limit)
	path := "resources.limits.memory"

	failed_paths := sprintf("spec.template.spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds memory-limit", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob exceeds memory-limit 
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]

	memory_limit := container.resources.limits.memory
	is_limit_exceeded_memory(memory_limit)
	path := "resources.limits.memory"

	failed_paths := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].%v", [format_int(i, 10), path])

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v exceeds memory-limit", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [failed_paths],
		"failedPaths": [failed_paths],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

######################################################################################################


is_limit_exceeded_memory(memory_limit) {
	is_min_limit_exceeded_memory(memory_limit)
}

is_limit_exceeded_memory(memory_limit) {
	is_max_limit_exceeded_memory(memory_limit)
}

is_req_exceeded_memory(memory_req) {
	is_max_request_exceeded_memory(memory_req)
}

is_req_exceeded_memory(memory_req) {
	is_min_request_exceeded_memory(memory_req)
}

# helpers

is_max_limit_exceeded_memory(memory_limit) {
	memory_limit_max := data.postureControlInputs.memory_limit_max[_]
	compare_max(memory_limit_max, memory_limit)
}

is_min_limit_exceeded_memory(memory_limit) {
	memory_limit_min := data.postureControlInputs.memory_limit_min[_]
	compare_min(memory_limit_min, memory_limit)
}

is_max_request_exceeded_memory(memory_req) {
	memory_req_max := data.postureControlInputs.memory_request_max[_]
	compare_max(memory_req_max, memory_req)
}

is_min_request_exceeded_memory(memory_req) {
	memory_req_min := data.postureControlInputs.memory_request_min[_]
	compare_min(memory_req_min, memory_req)
}


##############
# helpers

# Compare two Kubernetes memory quantities by normalizing both sides to bytes.
# Supports binary (Ki/Mi/Gi/Ti/Pi/Ei), decimal (k/K/M/G/T/P/E) and unitless byte counts.
compare_max(max, given) {
	mem_to_bytes(given) > mem_to_bytes(max)
}

compare_min(min, given) {
	mem_to_bytes(given) < mem_to_bytes(min)
}

# Parse a Kubernetes memory quantity string into bytes.
# Order matters: binary two-char suffixes are checked before single-char decimal
# suffixes so "Mi" is not misread as "M".
mem_to_bytes(q) = n {
	s := sprintf("%v", [q])
	endswith(s, "Ki")
	n := to_number(trim_suffix(s, "Ki")) * 1024
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "Mi")
	n := to_number(trim_suffix(s, "Mi")) * 1048576
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "Gi")
	n := to_number(trim_suffix(s, "Gi")) * 1073741824
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "Ti")
	n := to_number(trim_suffix(s, "Ti")) * 1099511627776
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "Pi")
	n := to_number(trim_suffix(s, "Pi")) * 1125899906842624
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "Ei")
	n := to_number(trim_suffix(s, "Ei")) * 1152921504606846976
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "m")
	n := to_number(trim_suffix(s, "m")) / 1000
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "k")
	n := to_number(trim_suffix(s, "k")) * 1000
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "K")
	n := to_number(trim_suffix(s, "K")) * 1000
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "M")
	n := to_number(trim_suffix(s, "M")) * 1000000
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "G")
	n := to_number(trim_suffix(s, "G")) * 1000000000
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "T")
	n := to_number(trim_suffix(s, "T")) * 1000000000000
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "P")
	n := to_number(trim_suffix(s, "P")) * 1000000000000000
} else = n {
	s := sprintf("%v", [q])
	endswith(s, "E")
	n := to_number(trim_suffix(s, "E")) * 1000000000000000000
} else = n {
	n := to_number(q)
}
