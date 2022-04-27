package armo_builtins


# Fails if pod does not have container with readinessProbe
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	not container.readinessProbe
	fix_path := {"path": sprintf("spec.containers[%v].readinessProbe", [format_int(i, 10)]), "value": "YOUR_VALUE"}
	msga := {
		"alertMessage": sprintf("Container: %v does not have readinessProbe", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"fixPaths": [fix_path],
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not have container with readinessProbe
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
    not container.readinessProbe
	fix_path := {"path": sprintf("spec.template.spec.containers[%v].readinessProbe", [format_int(i, 10)]), "value": "YOUR_VALUE"}
	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have readinessProbe", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"fixPaths": [fix_path],
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if cronjob does not have container with readinessProbe
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    not container.readinessProbe
	fix_path := {"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].readinessProbe", [format_int(i, 10)]), "value": "YOUR_VALUE"}
    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have readinessProbe", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"fixPaths": [fix_path],
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}
