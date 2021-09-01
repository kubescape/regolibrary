package armo_builtins


# Fails if pod has hostPID enabled
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	isHostPID(pod.spec)
	msga := {
		"alertMessage": sprintf("Pod: %v has hostPID enabled", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if pod has hostIPC enabled
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	isHostIPC(pod.spec)
	msga := {
		"alertMessage": sprintf("Pod: %v has hostIPC enabled", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}


# Fails if workload has hostPID enabled
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	isHostPID(wl.spec.template.spec)
    msga := {
	"alertMessage": sprintf("%v: %v has a pod with hostPID enabled", [wl.kind, wl.metadata.name]),
		"alertScore": 9,
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
	isHostIPC(wl.spec.template.spec)
    msga := {
	"alertMessage": sprintf("%v: %v has a pod with hostIPC enabled", [wl.kind, wl.metadata.name]),
		"alertScore": 9,
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
	isHostPID(wl.spec.jobTemplate.spec.template.spec)
    msga := {
	"alertMessage": sprintf("CronJob: %v has a pod with hostPID enabled", [wl.metadata.name]),
		"alertScore": 9,
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
	isHostIPC(wl.spec.jobTemplate.spec.template.spec)
    msga := {
	"alertMessage": sprintf("CronJob: %v has a pod with hostIPC enabled", [wl.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Check that hostPID and hostIPC are set to false. Default is false. Only in pod spec


isHostPID(podspec){
    podspec.hostPID == true
}

isHostIPC(podspec){
     podspec.hostIPC == true
}