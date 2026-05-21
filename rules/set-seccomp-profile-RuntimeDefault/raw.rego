package armo_builtins

import rego.v1

# Fails if pod does not define seccompProfile as RuntimeDefault
deny contains msga if {
	wl := input[_]
	wl.kind == "Pod"
	wl_spec := wl.spec
	path_to_containers := ["spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	path_to_search := ["securityContext", "seccompProfile", "type"]

	seccompProfile_result := get_seccompProfile_definition(wl_spec, container, i, path_to_containers, path_to_search)
	seccompProfile_result.failed == true

	msga := {
		"alertMessage": sprintf("Pod: %v does not define seccompProfile as RuntimeDefault", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": seccompProfile_result.failed_path,
		"failedPaths": seccompProfile_result.failed_path,
		"fixPaths": seccompProfile_result.fix_path,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if workload does not define seccompProfile as RuntimeDefault
deny contains msga if {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	wl_spec := wl.spec.template.spec
	path_to_containers := ["spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	path_to_search := ["securityContext", "seccompProfile", "type"]

	seccompProfile_result := get_seccompProfile_definition(wl_spec, container, i, path_to_containers, path_to_search)
	seccompProfile_result.failed == true

	msga := {
		"alertMessage": sprintf("Workload: %v does not define seccompProfile as RuntimeDefault", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": seccompProfile_result.failed_path,
		"failedPaths": seccompProfile_result.failed_path,
		"fixPaths": seccompProfile_result.fix_path,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if CronJob does not define seccompProfile as RuntimeDefault
deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	wl_spec := wl.spec.jobTemplate.spec.template.spec
	path_to_containers := ["spec", "jobTemplate", "spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	path_to_search := ["securityContext", "seccompProfile", "type"]

	seccompProfile_result := get_seccompProfile_definition(wl_spec, container, i, path_to_containers, path_to_search)
	seccompProfile_result.failed == true

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not define seccompProfile as RuntimeDefault", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": seccompProfile_result.failed_path,
		"failedPaths": seccompProfile_result.failed_path,
		"fixPaths": seccompProfile_result.fix_path,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# container definition takes precedence
get_seccompProfile_definition(wl, container, i, path_to_containers, path_to_search) := seccompProfile_result if {
	container.securityContext.seccompProfile.type == "RuntimeDefault"
	seccompProfile_result := {"failed": false, "failed_path": [], "fix_path": []}
} else := seccompProfile_result if {
	container.securityContext.seccompProfile.type != "RuntimeDefault"
	failed_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)])
	seccompProfile_result := {"failed": true, "failed_path": [failed_path], "fix_path": []}
} else := seccompProfile_result if {
	wl.securityContext.seccompProfile.type == "RuntimeDefault"
	seccompProfile_result := {"failed": false, "failed_path": [], "fix_path": []}
} else := seccompProfile_result if {
	wl.securityContext.seccompProfile.type != "RuntimeDefault"
	failed_path := sprintf("%s.%s", [trim_suffix(concat(".", path_to_containers), ".containers"), concat(".", path_to_search)])
	seccompProfile_result := {"failed": true, "failed_path": [failed_path], "fix_path": []}
} else := seccompProfile_result if {
	fix_path := [{"path": sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)]), "value": "RuntimeDefault"}]
	seccompProfile_result := {"failed": true, "failed_path": [], "fix_path": fix_path}
}
