# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails if a Windows pod does not define gmsaCredentialSpecName
deny contains msga if {
	path_to_search := ["securityContext", "windowsOptions", "gmsaCredentialSpecName"]
	path_to_containers := ["spec", "containers"]
	wl := input[_]
	wl.kind == "Pod"
	spec := wl.spec
	is_windows_workload(spec)
	no_field_in_securityContext(spec, path_to_search)

	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	no_field_in_securityContext(container, path_to_search)

	fix_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)])
	fixPaths := [{"path": fix_path, "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Pod: %v does not define 'securityContext.windowsOptions.gmsaCredentialSpecName'", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if a Windows workload does not define gmsaCredentialSpecName
deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	path_to_search := ["securityContext", "windowsOptions", "gmsaCredentialSpecName"]
	path_to_containers := ["spec", "template", "spec", "containers"]
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	spec := wl.spec.template.spec
	is_windows_workload(spec)
	no_field_in_securityContext(spec, path_to_search)

	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	no_field_in_securityContext(container, path_to_search)

	fix_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)])
	fixPaths := [{"path": fix_path, "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Workload: %v does not define 'securityContext.windowsOptions.gmsaCredentialSpecName'", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if a Windows CronJob does not define gmsaCredentialSpecName
deny contains msga if {
	path_to_search := ["securityContext", "windowsOptions", "gmsaCredentialSpecName"]
	path_to_containers := ["spec", "jobTemplate", "spec", "template", "spec", "containers"]
	wl := input[_]
	wl.kind == "CronJob"
	spec := wl.spec.jobTemplate.spec.template.spec
	is_windows_workload(spec)
	no_field_in_securityContext(spec, path_to_search)

	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	no_field_in_securityContext(container, path_to_search)

	fix_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)])
	fixPaths := [{"path": fix_path, "value": "YOUR_VALUE"}]
	msga := {
		"alertMessage": sprintf("CronJob: %v does not define 'securityContext.windowsOptions.gmsaCredentialSpecName'", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

no_field_in_securityContext(spec, path_to_search) if {
	object.get(spec, path_to_search, "") == ""
}

# is_windows_workload restricts the rule to pods/templates explicitly targeting Windows nodes,
# since gmsaCredentialSpecName is only meaningful for Windows containers.
is_windows_workload(spec) if {
	spec.os.name == "windows"
}

is_windows_workload(spec) if {
	spec.nodeSelector["kubernetes.io/os"] == "windows"
}
