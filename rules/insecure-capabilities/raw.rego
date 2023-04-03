package armo_builtins
import data
import data.cautils as cautils

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	start_of_path := "spec."
    result := is_dangerous_capabilities(container, start_of_path, i)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have dangerous capabilities", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": result,
		"fixPaths": [],
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
	start_of_path := "spec.template.spec."
    result := is_dangerous_capabilities(container, start_of_path, i)
	msga := {
		"alertMessage": sprintf("container: %v in workload: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	start_of_path := "spec.jobTemplate.spec.template.spec."
    result := is_dangerous_capabilities(container, start_of_path, i)
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

is_dangerous_capabilities(container, start_of_path, i) = path {
	# see default-config-inputs.json for list values
    insecureCapabilities := data.postureControlInputs.insecureCapabilities
	path = [sprintf("%vcontainers[%v].securityContext.capabilities.add[%v]", [start_of_path, format_int(i, 10), format_int(k, 10)]) | capability = container.securityContext.capabilities.add[k]; cautils.list_contains(insecureCapabilities, capability)]
	count(path) > 0
}