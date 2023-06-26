package armo_builtins

import data.cautils

# Fails if container has bash/cmd inside it
# Pods
deny [msga] {
    pod := input[_]
    container := pod.spec.containers[i]
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]
    is_bash_container(scan)
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("the following container: %v has bash/cmd inside it.", [container.name]),
		"alertScore": 6,
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [pod],
			"externalObjects": {
				"container" : [{container.name}]
			}
		},
	}
}


# Workloads
deny [msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]
    is_bash_container(scan)


    msga := {
		"alertMessage": sprintf("the following container: %v has bash/cmd inside it.", [container.name]),
		"alertScore": 6,
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl],
			"externalObjects": {
				"container" : [{container.name}]
			}
		},
	}
}

# Cronjobs
deny [msga] {
    wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]
    is_bash_container(scan)

    msga := {
		"alertMessage": sprintf("the following container: %v has bash/cmd inside it.", [container.name]),
		"alertScore": 6,
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl],
			"externalObjects": {
				"container" : [{container.name}]
			}
		},
	}
}


is_bash_container(scan) {
	# see default-config-inputs.json for list values
	shells :=  data.postureControlInputs.listOfDangerousArtifacts
	shell := shells[_]
	cautils.list_contains(scan.listOfDangerousArtifacts, shell)
}
