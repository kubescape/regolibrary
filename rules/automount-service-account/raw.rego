package armo_builtins

# Fails if user account mount tokens in pod by default
deny [msga]{
    service_accounts := [service_account |  service_account= input[_]; service_account.kind == "ServiceAccount"]
    service_account := service_accounts[_]
    result := is_auto_mount(service_account)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    msga := {
	    "alertMessage": sprintf("the following service account: %v in the following namespace: %v mounts service account tokens in pods by default", [service_account.metadata.name, service_account.metadata.namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"fixPaths": fixed_path,
		"deletePaths": failed_path,
		"failedPaths": failed_path,
		"alertObject": {
			"k8sApiObjects": [service_account]
		}
	}
}    


 #  -- ----     For workloads     -- ----   
# Fails if pod mount tokens  by default (either by its config or by its SA config)

 # POD  
deny [msga]{
    pod := input[_]
	pod.kind == "Pod"

	start_of_path := "spec."
	wl_namespace := pod.metadata.namespace
	result := is_sa_auto_mounted(pod.spec, start_of_path, wl_namespace)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    msga := {
	    "alertMessage": sprintf("Pod: %v in the following namespace: %v mounts service account tokens by default", [pod.metadata.name, pod.metadata.namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"fixPaths": fixed_path,
		"deletePaths": failed_path,
		"failedPaths": failed_path,
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
	start_of_path := "spec.template.spec."

	wl_namespace := wl.metadata.namespace
	result := is_sa_auto_mounted(wl.spec.template.spec, start_of_path, wl_namespace)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

	msga := {
		"alertMessage":  sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixed_path,
		"deletePaths": failed_path,
		"failedPaths": failed_path,
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
	start_of_path := "spec.jobTemplate.spec.template.spec."
   
	wl_namespace := wl.metadata.namespace
	result := is_sa_auto_mounted(wl.spec.jobTemplate.spec.template.spec, start_of_path, wl.metadata)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    msga := {
		"alertMessage": sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixed_path,
		"deletePaths": failed_path,
		"failedPaths": failed_path,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



 #  -- ----     For workloads     -- ----     
is_sa_auto_mounted(spec, start_of_path, wl_metadata) = [failed_path, fix_path]   {
	# automountServiceAccountToken not in pod spec
	not spec.automountServiceAccountToken == false
	not spec.automountServiceAccountToken == true

	# check if SA  automount by default
	sa := input[_]
	is_same_sa(spec, sa.metadata.name)
	is_same_namespace(sa.metadata , wl_metadata)
	not sa.automountServiceAccountToken == false

	# path is pod spec
	fix_path = { "path": sprintf("%vautomountServiceAccountToken", [start_of_path]), "value": "false"}
	failed_path = ""
}

get_failed_path(paths) = [paths[0]] {
	paths[0] != ""
} else = []


get_fixed_path(paths) = [paths[1]] {
	paths[1] != ""
} else = []

is_sa_auto_mounted(spec, start_of_path, wl_namespace) =  [failed_path, fix_path]  {
	# automountServiceAccountToken set to true in pod spec
	spec.automountServiceAccountToken == true
	
	# SA automount by default
	service_accounts := [service_account | service_account = input[_]; service_account.kind == "ServiceAccount"]
	count(service_accounts) > 0
	sa := service_accounts[_]
	is_same_sa(spec, sa.metadata.name)
	is_same_namespace(sa.metadata , wl_namespace)
	not sa.automountServiceAccountToken == false

	failed_path = sprintf("%vautomountServiceAccountToken", [start_of_path])
	fix_path = ""
}

is_sa_auto_mounted(spec, start_of_path, wl_namespace) =  [failed_path, fix_path]  {
	# automountServiceAccountToken set to true in pod spec
	spec.automountServiceAccountToken == true
	
	# No SA (yaml scan)
	service_accounts := [service_account | service_account = input[_]; service_account.kind == "ServiceAccount"]
	count(service_accounts) == 0
	failed_path = sprintf("%vautomountServiceAccountToken", [start_of_path])
	fix_path = ""
}



 #  -- ----     For SAs     -- ----     
is_auto_mount(service_account)  =  [failed_path, fix_path]  {
	service_account.automountServiceAccountToken == true
	failed_path = "automountServiceAccountToken"
	fix_path = ""
}

is_auto_mount(service_account)=  [failed_path, fix_path]  {
	not service_account.automountServiceAccountToken == false
	not service_account.automountServiceAccountToken == true
	fix_path = {"path": "automountServiceAccountToken", "value": "false"}
	failed_path = ""
}

is_same_sa(spec, serviceAccountName) {
	spec.serviceAccountName == serviceAccountName
}

is_same_sa(spec, serviceAccountName) {
	not spec.serviceAccountName 
	serviceAccountName == "default"
}


is_same_namespace(metadata1, metadata2) {
	metadata1.namespace == metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
	not metadata1.namespace
	not metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
	not metadata2.namespace
	metadata1.namespace == "default"
}

is_same_namespace(metadata1, metadata2) {
	not metadata1.namespace
	metadata2.namespace == "default"
}