package armo_builtins

# Fails if user account mount tokens in pod by default
deny [msga]{
    serviceaccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceaccounts[_]
    result := isAutoMount(serviceaccount)
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

    msga := {
	    "alertMessage": sprintf("the following service account: %v in the following namespace: %v mounts service account tokens in pods by default", [serviceaccount.metadata.name, serviceaccount.metadata.namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"fixPaths": fixedPath,
		"failedPaths": failedPath,
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
	result := isSAAutoMounted(pod.spec, begginingOfPath, wlNamespace)
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

    msga := {
	    "alertMessage": sprintf("Pod: %v in the following namespace: %v mounts service account tokens by default", [pod.metadata.name, pod.metadata.namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"fixPaths": fixedPath,
		"failedPaths": failedPath,
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
	result := isSAAutoMounted(wl.spec.template.spec, begginingOfPath, wlNamespace)
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

	msga := {
		"alertMessage":  sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixedPath,
		"failedPaths": failedPath,
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
	result := isSAAutoMounted(wl.spec.jobTemplate.spec.template.spec, begginingOfPath, wlNamespace)
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

    msga := {
		"alertMessage": sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixedPath,
		"failedPaths": failedPath,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



 #  -- ----     For workloads     -- ----     
isSAAutoMounted(spec, begginingOfPath, wlNamespace) = [failedPath, fixPath]   {
	# automountServiceAccountToken not in pod spec
	not spec.automountServiceAccountToken == false
	not spec.automountServiceAccountToken == true

	# check if SA  automount by default
	sa := input[_]
	isSameSA(spec, sa.metadata.name)
	isSameNamespace(sa.metadata.namespace , wlNamespace)
	not sa.automountServiceAccountToken == false

	# path is pod spec
	fixPath = { "path": sprintf("%vautomountServiceAccountToken", [begginingOfPath]), "value": "false"}
	failedPath = ""
}

getFailedPath(paths) = [paths[0]] {
	paths[0] != ""
} else = []


getFixedPath(paths) = [paths[1]] {
	paths[1] != ""
} else = []

isSAAutoMounted(spec, begginingOfPath, wlNamespace) =  [failedPath, fixPath]  {
	# automountServiceAccountToken set to true in pod spec
	spec.automountServiceAccountToken == true
	
	# SA automount by default
	serviceaccounts := [serviceaccount | serviceaccount = input[_]; serviceaccount.kind == "ServiceAccount"]
	count(serviceaccounts) > 0
	sa := serviceaccounts[_]
	isSameSA(spec, sa.metadata.name)
	isSameNamespace(sa.metadata.namespace , wlNamespace)
	not sa.automountServiceAccountToken == false

	failedPath = sprintf("%vautomountServiceAccountToken", [begginingOfPath])
	fixPath = ""
}

isSAAutoMounted(spec, begginingOfPath, wlNamespace) =  [failedPath, fixPath]  {
	# automountServiceAccountToken set to true in pod spec
	spec.automountServiceAccountToken == true
	
	# No SA (yaml scan)
	serviceaccounts := [serviceaccount | serviceaccount = input[_]; serviceaccount.kind == "ServiceAccount"]
	count(serviceaccounts) == 0
	failedPath = sprintf("%vautomountServiceAccountToken", [begginingOfPath])
	fixPath = ""
}



 #  -- ----     For SAs     -- ----     
isAutoMount(serviceaccount)  =  [failedPath, fixPath]  {
	serviceaccount.automountServiceAccountToken == true
	failedPath = "automountServiceAccountToken"
	fixPath = ""
}

isAutoMount(serviceaccount)=  [failedPath, fixPath]  {
	not serviceaccount.automountServiceAccountToken == false
	not serviceaccount.automountServiceAccountToken == true
	fixPath = {"path": "automountServiceAccountToken", "value": "false"}
	failedPath = ""
}

isSameSA(spec, serviceAccountName) {
	spec.serviceAccountName == serviceAccountName
}

isSameSA(spec, serviceAccountName) {
	not spec.serviceAccountName 
	serviceAccountName == "default"
}


isSameNamespace(metadata1, metadata2) {
	metadata1.namespace == metadata2.namespace
}

isSameNamespace(metadata1, metadata2) {
	not metadata1.namespace
	not metadata2.namespace
}

isSameNamespace(metadata1, metadata2) {
	not metadata2.namespace
	metadata1.namespace == "default"
}

isSameNamespace(metadata1, metadata2) {
	not metadata1.namespace
	metadata2.namespace == "default"
}