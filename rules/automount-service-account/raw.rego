package armo_builtins

# Fails if user account mount tokens in pod by default
deny [msga]{
    serviceaccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceaccounts[_]
    path := isAutoMount(serviceaccount)

    msga := {
	    "alertMessage": sprintf("the following service account: %v in the following namespace: %v mounts service account tokens in pods by default", [serviceaccount.metadata.name, serviceaccount.metadata.namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [serviceaccount]
		}
	}
}    


 #  -- ----     For workloads     -- ----   
# Fails if pod mount tokens  by default (either by its config or by its SA config)

 # POD  
deny [msga]{
    pod := input[_]
	pod.kind == "Pod"

	begginingOfPath := "spec."
	wlNamespace := pod.metadata.namespace
	path := isSAAutoMounted(pod.spec, begginingOfPath, wlNamespace)

    msga := {
	    "alertMessage": sprintf("Pod: %v in the following namespace: %v mounts service account tokens by default", [pod.metadata.name, pod.metadata.namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}    

# WORKLOADS
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	begginingOfPath := "spec.template.spec."

	wlNamespace := wl.metadata.namespace
	path := isSAAutoMounted(wl.spec.template.spec, begginingOfPath, wlNamespace)

	msga := {
		"alertMessage":  sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# CRONJOB
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
   
	wlNamespace := wl.metadata.namespace
	path := isSAAutoMounted(wl.spec.jobTemplate.spec.template.spec, begginingOfPath, wlNamespace)

    msga := {
		"alertMessage": sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



 #  -- ----     For workloads     -- ----     
isSAAutoMounted(spec, begginingOfPath, wlNamespace) = path   {
	# automountServiceAccountToken not in pod spec
	not spec.automountServiceAccountToken == false
	not spec.automountServiceAccountToken == true

	# check if SA  automount by default
	sa := input[_]
	sa.metadata.name == spec.serviceAccountName
	sa.metadata.namespace == wlNamespace
	not sa.automountServiceAccountToken == false

	# path is pod spec
	path := sprintf("%v", [begginingOfPath])
}

isSAAutoMounted(spec, begginingOfPath, wlNamespace) = path   {
	# automountServiceAccountToken set to true in pod spec
	spec.automountServiceAccountToken == true
	
	# SA automount by default
	sa := input[_]
	sa.metadata.name == spec.serviceAccountName
	sa.metadata.namespace == wlNamespace
	not sa.automountServiceAccountToken == false

	path := sprintf("%vautomountServiceAccountToken", [begginingOfPath])
}



 #  -- ----     For SAs     -- ----     
isAutoMount(serviceaccount)  = path {
	path = "automountServiceAccountToken"
	serviceaccount.automountServiceAccountToken == true
}

isAutoMount(serviceaccount) = path {
	not serviceaccount.automountServiceAccountToken == false
	not serviceaccount.automountServiceAccountToken == true
	path = ""
}