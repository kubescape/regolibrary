package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    pod.metadata.namespace == "default"
	msga := {
		"alertMessage": sprintf("Pod: %v is running in the 'default' namespace", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}


deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	wl.metadata.namespace == "default"
	msga := {
		"alertMessage": sprintf("%v: %v has pods running in the 'default' namespace", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
    wl.metadata.namespace == "default"
	msga := {
		"alertMessage": sprintf("CronJob: %v had pods  running in the 'default' namespace", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


