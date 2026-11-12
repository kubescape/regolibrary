# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# input:
# apiversion:
# fails if pod that is not dashboard is associated to dashboard service account

deny contains msga if {
	pod := input[_]
	sa := service_account_field(pod.spec)
	sa.name == "kubernetes-dashboard"
	not startswith(pod.metadata.name, "kubernetes-dashboard")

	path := sprintf("spec.%v", [sa.field])

	msga := {
		"alertMessage": sprintf("the following pods: %s are associated with dashboard service account", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"deletePaths": [path],
		"failedPaths": [path],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# input:
# apiversion:
# fails if workload that is not dashboard is associated to dashboard service account

deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	sa := service_account_field(wl.spec.template.spec)
	sa.name == "kubernetes-dashboard"
	not startswith(wl.metadata.name, "kubernetes-dashboard")

	path := sprintf("spec.template.spec.%v", [sa.field])

	msga := {
		"alertMessage": sprintf("%v: %v is associated with dashboard service account", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [path],
		"failedPaths": [path],
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
	sa := service_account_field(wl.spec.jobTemplate.spec.template.spec)
	sa.name == "kubernetes-dashboard"
	not startswith(wl.metadata.name, "kubernetes-dashboard")

	path := sprintf("spec.jobTemplate.spec.template.spec.%v", [sa.field])

	msga := {
		"alertMessage": sprintf("the following cronjob: %s is associated with dashboard service account", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"deletePaths": [path],
		"failedPaths": [path],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# serviceAccount is the deprecated alias of serviceAccountName, which wins when
# both are set (the API server fills serviceAccountName in, but manifests in
# file scans can carry only the alias)
service_account_field(spec) := {"name": spec.serviceAccountName, "field": "serviceAccountName"} if {
	spec.serviceAccountName != ""
} else := {"name": spec.serviceAccount, "field": "serviceAccount"} if {
	spec.serviceAccount != ""
}
