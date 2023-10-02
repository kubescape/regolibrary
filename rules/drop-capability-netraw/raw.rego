package armo_builtins

import future.keywords.in

# Fails if pod does not drop the capability NET_RAW 
deny[msga] {
	wl := input[_]
	wl.kind == "Pod"
	path_to_containers := ["spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	path_to_search := ["securityContext", "capabilities"]
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
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	path_to_containers := ["spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	path_to_search := ["securityContext", "capabilities"]
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
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	path_to_containers := ["spec", "jobTemplate", "spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	path_to_search := ["securityContext", "capabilities"]
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
container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search) = [failed_path, fix_path] {
	path_to_drop := array.concat(path_to_search, ["drop"])
	drop_list := object.get(container, path_to_drop, [])
	not "NET_RAW" in drop_list
	not "ALL" in drop_list
	not "all" in drop_list
	fixpath := sprintf("%s[%d].%s[%d]", [concat(".", path_to_containers), i, concat(".", path_to_drop), count(drop_list)])
	fix_path := [{"path": fixpath, "value": "NET_RAW"}]
	failed_path := ""
}

# Checks if workload drops all capabilities but adds NET_RAW capability
container_doesnt_drop_NET_RAW(container, i, path_to_containers, path_to_search) = [failed_path, fix_path] {
	path_to_drop := array.concat(path_to_search, ["drop"])
	drop_list := object.get(container, path_to_drop, [])
	all_in_list(drop_list)
	path_to_add := array.concat(path_to_search, ["add"])
	add_list := object.get(container, path_to_add, [])
	"NET_RAW" in add_list
	failed_path := [sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_add)])]
	fix_path := ""
}

all_in_list(list) {
	"all" in list
}

all_in_list(list) {
	"ALL" in list
}


get_failed_path(paths) = paths[0] {
	paths[0] != ""
} else = []


get_fixed_path(paths) = paths[1] {
	paths[1] != ""
} else = []

