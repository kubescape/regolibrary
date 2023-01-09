package armo_builtins

import future.keywords.in

# Fails if pod does not drop the capability NET_RAW 
deny[msga] {
	wl := input[_]
	wl.kind == "Pod"
	path_to_containers := ["spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	path_to_search := ["securityContext", "capabilities", "drop"]
	length := container_doesnt_drop_NET_RAW(container, path_to_search)

	fix_path := sprintf("%s[%d].%s[%d]", [concat(".", path_to_containers), i, concat(".", path_to_search), length])
	fixPaths := [{"path": fix_path, "value": "NET_RAW"}]

	msga := {
		"alertMessage": sprintf("Pod: %s does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
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

	path_to_search := ["securityContext", "capabilities", "drop"]
	length := container_doesnt_drop_NET_RAW(container, path_to_search)

	fix_path := sprintf("%s[%d].%s[%d]", [concat(".", path_to_containers), i, concat(".", path_to_search), length])
	fixPaths := [{"path": fix_path, "value": "NET_RAW"}]

	msga := {
		"alertMessage": sprintf("Workload: %v does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
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

	path_to_search := ["securityContext", "capabilities", "drop"]
	length := container_doesnt_drop_NET_RAW(container, path_to_search)

	fix_path := sprintf("%s[%d].%s[%d]", [concat(".", path_to_containers), i, concat(".", path_to_search), length])
	fixPaths := [{"path": fix_path, "value": "NET_RAW"}]

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

container_doesnt_drop_NET_RAW(container, path_to_search) = length {
	drop_list := object.get(container, path_to_search, [])
	length := count(drop_list)
	not "NET_RAW" in drop_list
}