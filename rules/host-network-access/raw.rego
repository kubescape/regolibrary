# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails if pod has hostNetwork enabled
deny contains msga if {
	path := "spec.hostNetwork"
	pods := [pod | pod = input[_]; pod.kind == "Pod"]
	pod := pods[_]

	is_host_network(pod.spec)
	msga := {
		"alertMessage": sprintf("Pod: %v is connected to the host network", [pod.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload has hostNetwork enabled
deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	path := "spec.template.spec.hostNetwork"
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	is_host_network(wl.spec.template.spec)
	msga := {
		"alertMessage": sprintf("%v: %v has a pod connected to the host network", [wl.kind, wl.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob has hostNetwork enabled
deny contains msga if {
	path := "spec.jobTemplate.spec.template.spec.hostNetwork"
	wl := input[_]
	wl.kind == "CronJob"
	is_host_network(wl.spec.jobTemplate.spec.template.spec)
	msga := {
		"alertMessage": sprintf("CronJob: %v has a pod connected to the host network", [wl.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

is_host_network(podspec) if {
	podspec.hostNetwork == true
}
