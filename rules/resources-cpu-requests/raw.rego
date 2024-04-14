package armo_builtins

# ==================================== no CPU requests =============================================
# Fails if pod does not have container with CPU request
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	not container.resources.requests.cpu

	fixPaths := [{"path": sprintf("spec.containers[%v].resources.requests.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v does not have CPU-limit or request", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not have container with CPU requests
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
    not container.resources.requests.cpu

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].resources.requests.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob does not have container with CPU requests
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    not container.resources.requests.cpu

	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].resources.requests.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have CPU-limit or request", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}
