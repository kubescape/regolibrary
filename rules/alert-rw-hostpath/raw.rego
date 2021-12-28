package armo_builtins

# input: pod
# apiversion: v1
# does: returns hostPath volumes

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    volumes := pod.spec.volumes
    volume := volumes[_]
    volume.hostPath
	container := pod.spec.containers[i]
	volumeMount := container.volumeMounts[k]
	volumeMount.name == volume.name
	begginingOfPath := "spec."
	result := isRWMount(volumeMount, begginingOfPath,  i, k)

    podname := pod.metadata.name

	msga := {
		"alertMessage": sprintf("pod: %v has: %v as hostPath volume", [podname, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

#handles majority of workload resources
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    volumes := wl.spec.template.spec.volumes
    volume := volumes[_]
    volume.hostPath
	container := wl.spec.template.spec.containers[i]
	volumeMount := container.volumeMounts[k]
	volumeMount.name == volume.name
	begginingOfPath := "spec.template.spec."
	result := isRWMount(volumeMount, begginingOfPath,  i, k)

	msga := {
		"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	
	}
}

#handles CronJobs
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    volumes := wl.spec.jobTemplate.spec.template.spec.volumes
    volume := volumes[_]
    volume.hostPath

	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	volumeMount := container.volumeMounts[k]
	volumeMount.name == volume.name
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
	result := isRWMount(volumeMount, begginingOfPath,  i, k)

	msga := {
	"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
	"packagename": "armo_builtins",
	"alertScore": 7,
	"failedPaths": [result],
	"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

isRWMount(mount, begginingOfPath,  i, k) = path {
 not mount.readOnly == true
 not mount.readOnly == false
 path = ""
}
isRWMount(mount, begginingOfPath,  i, k) = path {
  mount.readOnly == false
  path = sprintf("%vcontainers[%v].volumeMounts[%v].readOnly", [begginingOfPath, format_int(i, 10), format_int(k, 10)])
} 