# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails if pod does not drop the capability NET_RAW
deny contains msga if {
	path_to_containers := ["spec", "containers"]
	path_to_search := ["securityContext", "capabilities"]
	wl := input[_]
	wl.kind == "Pod"
	not is_windows_pod(wl.spec)
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	
	result := container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search)
	failedPaths := get_failed_path(result)
	fixPaths := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("Pod: %s does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": failedPaths,
		"failedPaths": failedPaths,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if pod init container does not drop the capability NET_RAW
deny contains msga if {
	path_to_containers := ["spec", "initContainers"]
	path_to_search := ["securityContext", "capabilities"]
	wl := input[_]
	wl.kind == "Pod"
	not is_windows_pod(wl.spec)
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	result := container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search)
	failedPaths := get_failed_path(result)
	fixPaths := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("Pod: %s does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": failedPaths,
		"failedPaths": failedPaths,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if pod ephemeral container does not drop the capability NET_RAW
deny contains msga if {
	path_to_containers := ["spec", "ephemeralContainers"]
	path_to_search := ["securityContext", "capabilities"]
	wl := input[_]
	wl.kind == "Pod"
	not is_windows_pod(wl.spec)
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	result := container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search)
	failedPaths := get_failed_path(result)
	fixPaths := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("Pod: %s does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": failedPaths,
		"failedPaths": failedPaths,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if workload does not drop the capability NET_RAW
deny contains msga if {
	path_to_containers := ["spec", "template", "spec", "containers"]
	path_to_search := ["securityContext", "capabilities"]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	not is_windows_pod(wl.spec.template.spec)
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	
	result := container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search)
	failedPaths := get_failed_path(result)
	fixPaths := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("Workload: %v does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": failedPaths,
		"failedPaths": failedPaths,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if workload init container does not drop the capability NET_RAW
deny contains msga if {
	path_to_containers := ["spec", "template", "spec", "initContainers"]
	path_to_search := ["securityContext", "capabilities"]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	not is_windows_pod(wl.spec.template.spec)
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	result := container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search)
	failedPaths := get_failed_path(result)
	fixPaths := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("Workload: %v does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": failedPaths,
		"failedPaths": failedPaths,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if CronJob does not drop the capability NET_RAW
deny contains msga if {
	path_to_search := ["securityContext", "capabilities"]
	path_to_containers := ["spec", "jobTemplate", "spec", "template", "spec", "containers"]
	wl := input[_]
	wl.kind == "CronJob"
	not is_windows_pod(wl.spec.jobTemplate.spec.template.spec)
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	
	result := container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search)
	failedPaths := get_failed_path(result)
	fixPaths := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": failedPaths,
		"failedPaths": failedPaths,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if CronJob init container does not drop the capability NET_RAW
deny contains msga if {
	path_to_search := ["securityContext", "capabilities"]
	path_to_containers := ["spec", "jobTemplate", "spec", "template", "spec", "initContainers"]
	wl := input[_]
	wl.kind == "CronJob"
	not is_windows_pod(wl.spec.jobTemplate.spec.template.spec)
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	result := container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search)
	failedPaths := get_failed_path(result)
	fixPaths := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": failedPaths,
		"failedPaths": failedPaths,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Checks if workload does not drop the capability NET_RAW
container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search) := [failed_path, fix_path] if {
	path_to_drop := array.concat(path_to_search, ["drop"])
	drop_list := object.get(container, path_to_drop, [])
	not has_capability(drop_list, "NET_RAW")
	not has_capability(drop_list, "ALL")
	fixpath := sprintf("%s[%d].%s[%d]", [concat(".", path_to_containers), i, concat(".", path_to_drop), count(drop_list)])
	fix_path := [{"path": fixpath, "value": "NET_RAW"}]
	failed_path := ""
}

# Checks if workload drops all capabilities but adds NET_RAW capability
container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search) := [failed_path, fix_path] if {
	path_to_drop := array.concat(path_to_search, ["drop"])
	drop_list := object.get(container, path_to_drop, [])
	has_capability(drop_list, "ALL")
	path_to_add := array.concat(path_to_search, ["add"])
	add_list := object.get(container, path_to_add, [])
	has_capability(add_list, "NET_RAW")
	failed_path := [sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_add)])]
	fix_path := ""
}

has_capability(list, name) if {
	some capability in list
	capability_name(capability) == name
}

# The API server doesn't normalize capability names: containerd upper-cases
# them and CRI-O also takes them with a CAP_ prefix, so compare them that way
capability_name(capability) := trim_prefix(upper(capability), "CAP_")

get_failed_path(paths) := paths[0] if {
	paths[0] != ""
} else := []

get_fixed_path(paths) := paths[1] if {
	paths[1] != ""
} else := []

# The API server rejects capabilities in a pod with spec.os.name set to windows
# (validateWindows in pkg/apis/core/validation), so such a pod can't apply the
# fix and is not evaluated here.
is_windows_pod(spec) if {
	spec.os.name == "windows"
}
