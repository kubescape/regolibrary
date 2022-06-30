package armo_builtins


# Returns for each Pod, what are the permission of its service account

deny[msga] {
   serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name
    
    pods := [pod | pod=input[_]; pod.kind =="Pod"]
    pod := pods[_]
    pod.spec.serviceAccountName == serviceAccountName

    not isNotAutoMount(serviceaccount, pod)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName

    roles := [role |  role = input[_]; role.kind == "Role"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

	msga := {
		"alertMessage": sprintf("Pod: %v has the following permissions in the cluster: %v", [pod.metadata.name, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
       "failedPaths": [""],
		"alertScore": 7,
        "alertObject": {
			"k8sApiObjects": [rolebinding, role, pod]
		}
	}
}

# Returns for each Pod, what are the permission of its service account
 deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name

    pods := [pod | pod=input[_]; pod.kind =="Pod"]
    pod := pods[_]
    pod.spec.serviceAccountName == serviceAccountName

    not isNotAutoMount(serviceaccount, pod)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

	msga := {
		"alertMessage": sprintf("Pod: %v has the following permissions in the cluster: %v", [pod.metadata.name, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
        "failedPaths": [""],
		"alertObject": {
				"k8sApiObjects": [rolebinding, role, pod]
		}
	}
}

# Returns for each Pod, what are the permission of its service account

 deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name

    pods := [pod | pod=input[_]; pod.kind =="Pod"]
    pod := pods[_]
    pod.spec.serviceAccountName == serviceAccountName

    not isNotAutoMount(serviceaccount, pod)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

	msga := {
		"alertMessage": sprintf("Pod: %v has the following permissions in the cluster: %v", [pod.metadata.name, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
        "failedPaths": [""],
        "alertObject": {
			"k8sApiObjects": [rolebinding, role, pod]
		}
	}
}




### ---------------- #####

 

# Returns for each Workloads, what are the permission of its service account
deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name

    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]

    wl.spec.template.spec.serviceAccountName == serviceAccountName

    not isNotAutoMount(serviceaccount, wl.spec.template)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName

    roles := [role |  role = input[_]; role.kind == "Role"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

    msga := {
		"alertMessage": sprintf("%v: %v has the following permissions in the cluster: %v", [wl.kind, wl.metadata.name, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
       "failedPaths": [""],
        "alertObject": {
			"k8sApiObjects": [rolebinding, role, wl]
		}
	}
}


# Returns for each Workloads, what are the permission of its service account
deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name

    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]

    wl.spec.template.spec.serviceAccountName == serviceAccountName

    not isNotAutoMount(serviceaccount, wl.spec.template)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

        msga := {
		"alertMessage": sprintf("%v: %v has the following permissions in the cluster: %v", [wl.kind, wl.metadata.name, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
       "failedPaths": [""],
        "alertObject": {
			"k8sApiObjects": [rolebinding, role, wl]
		}
	}
}



# Returns for each Workloads, what are the permission of its service account
deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name

    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]

    wl.spec.template.spec.serviceAccountName == serviceAccountName

    not isNotAutoMount(serviceaccount, wl.spec.template)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name


        msga := {
		"alertMessage": sprintf("%v: %v has the following permissions in the cluster: %v", [wl.kind, wl.metadata.name, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
       "failedPaths": [""],
        "alertObject": {
			"k8sApiObjects": [rolebinding, role, wl]
		}
	}
}




### ---------------- #####


# Returns for each Cronjob, what are the permission of its service account

deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name

	wl := input[_]
	wl.kind == "CronJob"
	wl.spec.jobTemplate.spec.template.spec.serviceAccountName  == serviceAccountName

    not isNotAutoMount(serviceaccount, wl.spec.jobTemplate.spec.template)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName

    roles := [role |  role = input[_]; role.kind == "Role"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

    msga := {
		"alertMessage": sprintf("Cronjob: %v has the following permissions in the cluster: %v", [wl.metadata.name, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
       "failedPaths": [""],
        "alertObject": {
			"k8sApiObjects": [rolebinding, role, wl]
		}
	}
}



# Returns for each Cronjob, what are the permission of its service account
deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name


	wl := input[_]
	wl.kind == "CronJob"
	wl.spec.jobTemplate.spec.template.spec.serviceAccountName  == serviceAccountName

    not isNotAutoMount(serviceaccount, wl.spec.jobTemplate.spec.template)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

    msga := {
		"alertMessage": sprintf("Cronjob: %v has the following permissions in the cluster: %v", [wl.metadata.name, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
       "failedPaths": [""],
        "alertObject": {
			"k8sApiObjects": [rolebinding, role, wl]
		}
	}
}


# Returns for each Cronjob, what are the permission of its service account
deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name


	wl := input[_]
	wl.kind == "CronJob"
	wl.spec.jobTemplate.spec.template.spec.serviceAccountName  == serviceAccountName

    not isNotAutoMount(serviceaccount, wl.spec.jobTemplate.spec.template)
     
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name


    msga := {
		"alertMessage": sprintf("Cronjob: %v has the following permissions in the cluster: %v", [wl.metadata.name, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
       "failedPaths": [""],
        "alertObject": {
			"k8sApiObjects": [rolebinding, role, wl]
		}
	}
}

# ===============================================================

isNotAutoMount(serviceaccount, pod) {
    pod.spec.automountServiceAccountToken == false
}
isNotAutoMount(serviceaccount, pod) {
    serviceaccount.automountServiceAccountToken == false
    not pod.spec["automountServiceAccountToken"]
}

