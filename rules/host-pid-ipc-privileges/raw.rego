package armo_builtins


# Fails if pod has hostPID enabled
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	is_host_pid(pod.spec)
	path := "spec.hostPID"
	msga := {
		"alertMessage": sprintf("Pod: %v has hostPID enabled", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if pod has hostIPC enabled
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	is_host_ipc(pod.spec)
	path := "spec.hostIPC"
	msga := {
		"alertMessage": sprintf("Pod: %v has hostIPC enabled", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}


# Fails if workload has hostPID enabled
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	is_host_pid(wl.spec.template.spec)
	path := "spec.template.spec.hostPID"
    msga := {
	"alertMessage": sprintf("%v: %v has a pod with hostPID enabled", [wl.kind, wl.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if workload has hostIPC enabled
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	is_host_ipc(wl.spec.template.spec)
	path := "spec.template.spec.hostIPC"
    msga := {
	"alertMessage": sprintf("%v: %v has a pod with hostIPC enabled", [wl.kind, wl.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob has hostPID enabled
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	is_host_pid(wl.spec.jobTemplate.spec.template.spec)
	path := "spec.jobTemplate.spec.template.spec.hostPID"
    msga := {
	"alertMessage": sprintf("CronJob: %v has a pod with hostPID enabled", [wl.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if cronjob has hostIPC enabled
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	is_host_ipc(wl.spec.jobTemplate.spec.template.spec)
	path := "spec.jobTemplate.spec.template.spec.hostIPC"
    msga := {
	"alertMessage": sprintf("CronJob: %v has a pod with hostIPC enabled", [wl.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Check that hostPID and hostIPC are set to false. Default is false. Only in pod spec


is_host_pid(podspec){
    podspec.hostPID == true
}

is_host_ipc(podspec){
     podspec.hostIPC == true
}