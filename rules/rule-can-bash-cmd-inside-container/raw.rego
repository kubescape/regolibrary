package armo_builtins
import data.cautils as cautils


# Fails if container has bash/cmd inside it 
# Pods
deny [msga] {
    pod := input[_]
    container := pod.spec.containers[i]
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]
    isBashContainer(scan)
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])
    
    msga := {
		"alertMessage": sprintf("the following container: %v has bash/cmd inside it.", [container.name]),
		"alertScore": 6,
		"failedPaths": [path],
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
    isBashContainer(scan)

    
    msga := {
		"alertMessage": sprintf("the following container: %v has bash/cmd inside it.", [container.name]),
		"alertScore": 6,
		"failedPaths": [path],
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
    isBashContainer(scan)

    msga := {
		"alertMessage": sprintf("the following container: %v has bash/cmd inside it.", [container.name]),
		"alertScore": 6,
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl],
			"externalObjects": {
				"container" : [{container.name}]
			}
		},
	}
}


isBashContainer(scan) {
    cautils.list_contains(scan.listOfDangerousArtifcats, "bin/bash")
}
isBashContainer(scan) {
    cautils.list_contains(scan.listOfDangerousArtifcats, "sbin/sh")
}
isBashContainer(scan) {
    cautils.list_contains(scan.listOfDangerousArtifcats, "bin/ksh")
}
isBashContainer(scan) {
    cautils.list_contains(scan.listOfDangerousArtifcats, "bin/tcsh")
}
isBashContainer(scan) {
    cautils.list_contains(scan.listOfDangerousArtifcats, "bin/zsh")
}
isBashContainer(scan) {
    cautils.list_contains(scan.listOfDangerousArtifcats, "usr/bin/scsh")
}
isBashContainer(scan) {
    cautils.list_contains(scan.listOfDangerousArtifcats, "bin/csh")
}
isBashContainer(scan) {
    cautils.list_contains(scan.listOfDangerousArtifcats, "bin/busybox")
}
isBashContainer(scan) {
    cautils.list_contains(scan.listOfDangerousArtifcats, "usr/bin/busybox")
}
