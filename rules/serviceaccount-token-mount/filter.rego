package armo_builtins

import rego.v1

deny contains msga if {
	wl := input[_]
	start_of_path := get_beginning_of_path(wl)

	msga := {
		"alertMessage": sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

get_beginning_of_path(workload) := start_of_path if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[workload.kind]
	start_of_path := ["spec", "template", "spec"]
}

get_beginning_of_path(workload) := start_of_path if {
	workload.kind == "Pod"
	start_of_path := ["spec"]
}

get_beginning_of_path(workload) := start_of_path if {
	workload.kind == "CronJob"
	start_of_path := ["spec", "jobTemplate", "spec", "template", "spec"]
}
