package armo_builtins

# Fails if pod has hostNetwork enabled
deny[msga] {
    pods := [ pod | pod = input[_] ; pod.kind == "Pod"]
    pod := pods[_]

	isHostNetwork(pod.spec)
	path := "spec.hostNetwork"
    msga := {
	"alertMessage": sprintf("Pod: %v is connected to the host network", [pod.metadata.name]),
		"alertScore": 9,
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload has hostNetwork enabled
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	isHostNetwork(wl.spec.template.spec)
	path := "spec.template.spec.hostNetwork"
    msga := {
	"alertMessage": sprintf("%v: %v has a pod connected to the host network", [wl.kind, wl.metadata.name]),
		"alertScore": 9,
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob has hostNetwork enabled
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	isHostNetwork(wl.spec.jobTemplate.spec.template.spec)
	path := "spec.jobTemplate.spec.template.spec"
    msga := {
	"alertMessage": sprintf("CronJob: %v has a pod connected to the host network", [wl.metadata.name]),
		"alertScore": 9,
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

isHostNetwork(podspec) {
    podspec.hostNetwork == true
}