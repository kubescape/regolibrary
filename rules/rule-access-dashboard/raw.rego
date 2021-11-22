package armo_builtins

# input: roleBinding
# apiversion: v1
# fails if a subject that is not dashboard service account is bound to dashboard role

deny[msga] {
	roleBinding := input[_]
    roleBinding.kind == "RoleBinding"
    roleBinding.roleRef.name == "kubernetes-dashboard"
    subject := roleBinding.subjects[_]
    subject.name != "kubernetes-dashboard"
    subject.kind != "ServiceAccount"

	msga := {
		"alertMessage": sprintf("the following subjects: %s are bound to dashboard role/clusterrole", [subject.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
         "alertObject": {
			"k8sApiObjects": [roleBinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}

# input: clusterRoleBinding
# apiversion: v1
# fails if a subject that is not dashboard service account is bound to dashboard role

deny[msga] {
	roleBinding := input[_]
    roleBinding.kind == "ClusterRoleBinding"
    roleBinding.roleRef.name == "kubernetes-dashboard"
    subject := roleBinding.subjects[_]
    subject.name != "kubernetes-dashboard"
    subject.kind != "ServiceAccount"

	msga := {
		"alertMessage": sprintf("the following subjects: %s are bound to dashboard role/clusterrole", [subject.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [roleBinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
	}
}

# input: 
# apiversion: 
# fails if pod that is not dashboard is associated to dashboard service account

deny[msga] {
    pod := input[_]
    pod.spec.serviceaccountname == "kubernetes-dashboard"
    not startswith(pod.metadata.name, "kubernetes-dashboard")
	path := "spec.serviceaccountname"
	msga := {
		"alertMessage": sprintf("the following pods: %s are associated with dashboard service account", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
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
    wl.spec.template.spec.serviceaccountname == "kubernetes-dashboard"
    not startswith(wl.metadata.name, "kubernetes-dashboard")
	path := "spec.template.spec.serviceaccountname"
	msga := {
		"alertMessage": sprintf("%v: %v is associated with dashboard service account", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
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
    wl.spec.jobTemplate.spec.template.spec.serviceaccountname == "kubernetes-dashboard"
    not startswith(wl.metadata.name, "kubernetes-dashboard")
	path := "spec.jobTemplate.spec.template.spec.serviceaccountname"
	msga := {
		"alertMessage": sprintf("the following cronjob: %s is associated with dashboard service account", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}