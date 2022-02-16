package armo_builtins


# Fails if  container does not have livenessProbe - for pod
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	not container.livenessProbe
	fixPath := {"path": sprintf("spec.containers[%v].livenessProbe", [format_int(i, 10)]), "value": "YOUR_VALUE"}
	msga := {
		"alertMessage": sprintf("Container: %v does not have livenessProbe", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 4,
		"fixPaths": [fixPath],
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if  container does not have livenessProbe - for wl
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
    not container.livenessProbe
	fixPath := {"path": sprintf("spec.template.spec.containers[%v].livenessProbe", [format_int(i, 10)]), "value": "YOUR_VALUE"}
	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have livenessProbe", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 4,
		"fixPaths": [fixPath],
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if  container does not have livenessProbe - for cronjob
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    not container.livenessProbe
	fixPath := {"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].livenessProbe", [format_int(i, 10)]), "value": "YOUR_VALUE"}
    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have livenessProbe", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 4,
		"fixPaths": [fixPath],
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}
