package armo_builtins

import rego.v1

# input:
# apiversion:
# fails if pod that is not dashboard is associated to dashboard service account

deny contains msga if {
	pod := input[_]
	pod.spec.serviceAccountName == "kubernetes-dashboard"
	not startswith(pod.metadata.name, "kubernetes-dashboard")

	msga := {
		"alertMessage": sprintf("the following pods: %s are associated with dashboard service account", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"deletePaths": ["spec.serviceAccountName"],
		"failedPaths": ["spec.serviceAccountName"],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# input:
# apiversion:
# fails if workload that is not dashboard is associated to dashboard service account

deny contains msga if {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	wl.spec.template.spec.serviceAccountName == "kubernetes-dashboard"
	not startswith(wl.metadata.name, "kubernetes-dashboard")

	msga := {
		"alertMessage": sprintf("%v: %v is associated with dashboard service account", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": ["spec.template.spec.serviceAccountName"],
		"failedPaths": ["spec.template.spec.serviceAccountName"],
		"alertScore": 7,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# input:
# apiversion:
# fails if CronJob that is not dashboard is associated to dashboard service account

deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	wl.spec.jobTemplate.spec.template.spec.serviceAccountName == "kubernetes-dashboard"
	not startswith(wl.metadata.name, "kubernetes-dashboard")

	msga := {
		"alertMessage": sprintf("the following cronjob: %s is associated with dashboard service account", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"deletePaths": ["spec.jobTemplate.spec.template.spec.serviceAccountName"],
		"failedPaths": ["spec.jobTemplate.spec.template.spec.serviceAccountName"],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
