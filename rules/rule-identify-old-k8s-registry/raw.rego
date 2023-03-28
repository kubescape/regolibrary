package armo_builtins
import data

deprecatedK8sRepo[msga] {
	pod := input[_]
	pod.metadata.namespace == "kube-system"
	k := pod.kind
	k == "Pod"
	container := pod.spec.containers[i]
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    deprecated_registry(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from the deprecated k8s.gcr.io", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [pod]
		}
    }
}

deprecatedK8sRepo[msga] {
	wl := input[_]
	wl.metadata.namespace == "kube-system"
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    deprecated_registry(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from the deprecated k8s.gcr.io", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

deprecatedK8sRepo[msga] {
	wl := input[_]
	wl.metadata.namespace == "kube-system"
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    deprecated_registry(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from the deprecated k8s.gcr.io", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

deprecated_registry(image){
	startswith(image, "k8s.gcr.io/")
}
