package armo_builtins
import data

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
    result := isDangerousCapabilities(container, i)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have dangerous capabilities", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
    result := isDangerousCapabilities(container, i)
	msga := {
		"alertMessage": sprintf("container: %v in workload: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
    result := isDangerousCapabilities(container, i)
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

isDangerousCapabilities(container, i) = path {
    insecureCapabilities := data.postureControlInputs.insecureCapabilities
    insecureCapabilitie := insecureCapabilities[_]
	capabilite := container.securityContext.capabilities.add[k]
    capabilite == insecureCapabilitie
	path := sprintf("spec.containers[%v].securityContext.capabilities.add[%v]", [format_int(i, 10), format_int(k, 10)])
}