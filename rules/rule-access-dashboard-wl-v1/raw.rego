package armo_builtins

# input: 
# apiversion: 
# fails if pod that is not dashboard is associated to dashboard service account

deny[msga] {
    pod := input[_]
    pod.spec.serviceAccountName == "kubernetes-dashboard"
    not startswith(pod.metadata.name, "kubernetes-dashboard")

	msga := {
		"alertMessage": sprintf("the following pods: %s are associated with dashboard service account", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"deletePaths": ["spec.serviceaccountname"],
		"failedPaths": ["spec.serviceaccountname"],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# input: 
# apiversion: 
# fails if workload that is not dashboard is associated to dashboard service account

deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    wl.spec.template.spec.serviceAccountName == "kubernetes-dashboard"
    not startswith(wl.metadata.name, "kubernetes-dashboard")

	msga := {
		"alertMessage": sprintf("%v: %v is associated with dashboard service account", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": ["spec.template.spec.serviceaccountname"],
		"failedPaths": ["spec.template.spec.serviceaccountname"],
		"alertScore": 7,
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# input: 
# apiversion: 
# fails if CronJob that is not dashboard is associated to dashboard service account

deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
    wl.spec.jobTemplate.spec.template.spec.serviceAccountName == "kubernetes-dashboard"
    not startswith(wl.metadata.name, "kubernetes-dashboard")

	msga := {
		"alertMessage": sprintf("the following cronjob: %s is associated with dashboard service account", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"deletePaths": ["spec.jobTemplate.spec.template.spec.serviceaccountname"],
		"failedPaths": ["spec.jobTemplate.spec.template.spec.serviceaccountname"],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}