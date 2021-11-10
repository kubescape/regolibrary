package armo_builtins
import data


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[_]
    isDangerousCapabilities(container)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have dangerous capabilities", [container.name, pod.metadata.name]),
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
	container := wl.spec.template.spec.containers[_]
    isDangerousCapabilities(container)
	msga := {
		"alertMessage": sprintf("container: %v in workload: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
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
	container := wl.spec.jobTemplate.spec.template.spec.containers[_]
    isDangerousCapabilities(container)
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

isDangerousCapabilities(container){
    dangerousCapabilities := data.postureControlInputs.dangerousCapabilities
    dangerousCapabilitie := dangerousCapabilities[_]
    contains(container.securityContext.capabilities.add[_], dangerousCapabilitie)
}