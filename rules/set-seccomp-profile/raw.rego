package armo_builtins

# Fails if pod does not define seccompProfile
deny[msga] {
    wl := input[_]
    wl.kind == "Pod"
    spec := wl.spec
	path_to_search := ["securityContext", "seccompProfile"]
	seccompProfile_not_defined(spec, path_to_search)

	path_to_containers := ["spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
    seccompProfile_not_defined(container, path_to_search)

	fix_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)]) 
	fixPaths := [{"path": fix_path, "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Pod: %v does not define seccompProfile", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if workload does not define seccompProfile
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    spec := wl.spec.template.spec
	path_to_search := ["securityContext", "seccompProfile"]
	seccompProfile_not_defined(spec, path_to_search)

	path_to_containers := ["spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
    seccompProfile_not_defined(container, path_to_search)

	fix_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)]) 
	fixPaths := [{"path": fix_path, "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Workload: %v does not define seccompProfile", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if CronJob does not define seccompProfile
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    spec := wl.spec.jobTemplate.spec.template.spec
	path_to_search := ["securityContext", "seccompProfile"]
	seccompProfile_not_defined(spec, path_to_search)

	path_to_containers := ["spec", "jobTemplate", "spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
    seccompProfile_not_defined(container, path_to_search)

	fix_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)]) 
	fixPaths := [{"path": fix_path, "value": "YOUR_VALUE"}]


	msga := {
		"alertMessage": sprintf("Cronjob: %v does not define seccompProfile", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

seccompProfile_not_defined(spec, path_to_search){
	object.get(spec, path_to_search, "") == ""
}