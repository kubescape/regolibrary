# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

import data.cautils

deny contains msga if {
	start_of_path := "spec."
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	result := is_dangerous_capabilities(container, start_of_path, i, "containers")
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have dangerous capabilities", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": result,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	start_of_path := "spec."
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.initContainers[i]
	result := is_dangerous_capabilities(container, start_of_path, i, "initContainers")
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have dangerous capabilities", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": result,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	start_of_path := "spec."
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.ephemeralContainers[i]
	result := is_dangerous_capabilities(container, start_of_path, i, "ephemeralContainers")
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have dangerous capabilities", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": [],
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	start_of_path := "spec.template.spec."
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	result := is_dangerous_capabilities(container, start_of_path, i, "containers")
	msga := {
		"alertMessage": sprintf("container: %v in workload: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": result,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	start_of_path := "spec.template.spec."
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.initContainers[i]
	result := is_dangerous_capabilities(container, start_of_path, i, "initContainers")
	msga := {
		"alertMessage": sprintf("container: %v in workload: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": result,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}


deny contains msga if {
	start_of_path := "spec.jobTemplate.spec.template.spec."
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	result := is_dangerous_capabilities(container, start_of_path, i, "containers")
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": result,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	start_of_path := "spec.jobTemplate.spec.template.spec."
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.initContainers[i]
	result := is_dangerous_capabilities(container, start_of_path, i, "initContainers")
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  have dangerous capabilities", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": result,
		"failedPaths": result,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}


is_dangerous_capabilities(container, start_of_path, i, container_type) := path if {
	# see default-config-inputs.json for list values
	insecureCapabilities := [capability_name(listed) | some listed in data.postureControlInputs.insecureCapabilities]
	path = [sprintf("%v%v[%v].securityContext.capabilities.add[%v]", [start_of_path, container_type, format_int(i, 10), format_int(k, 10)]) | capability = container.securityContext.capabilities.add[k]; cautils.list_contains(insecureCapabilities, capability_name(capability))]
	count(path) > 0
}

# The API server doesn't normalize capability names: containerd upper-cases
# them and CRI-O also takes them with a CAP_ prefix, so compare them that way.
# Only ALL itself (in any case) means all capabilities to them: CAP_ALL
# becomes the unknown CAP_CAP_ALL in containerd, so it is not read as ALL.
capability_name(capability) := upper(capability) if {
	upper(capability) == "CAP_ALL"
} else := trim_prefix(upper(capability), "CAP_")
