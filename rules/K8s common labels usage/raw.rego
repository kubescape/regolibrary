package armo_builtins
# Deny mutating action unless user is in group owning the resource



deny[msga] {

	pod := input[_]
	pod.kind == "Pod"
	metadata := pod.metadata
	path := noK8sLabelOrNoK8sLabelUsage(metadata, "")

    msga := {
		"alertMessage": sprintf("in the following pod the kubernetes common labels are not defined: %v", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 0,
		"failedPaths": path,
         "alertObject": {
			"k8sApiObjects": [pod]
		}
     }
}


deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	wlMetadata := wl.metadata
	podMetadata := wl.spec.template.metadata
	begginingOfPodPath := "spec.template."
	path := noK8sLabelUsage(wlMetadata, podMetadata, begginingOfPodPath)

    msga := {
		"alertMessage": sprintf("%v: %v the kubernetes common labels are is not defined:", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 0,
		"failedPaths": path,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

#handles cronjob
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	wlMetadata := wl.metadata
	podMetadata := wl.spec.jobTemplate.spec.template.metadata
	begginingOfPodPath := "spec.jobTemplate.spec.template."
	path := noK8sLabelUsage(wlMetadata, podMetadata, begginingOfPodPath)


    msga := {
		"alertMessage": sprintf("the following cronjobs the kubernetes common labels are not defined: %v", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 0,
		"failedPaths": path,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}



# There is no label-usage in WL and also for his Pod
noK8sLabelUsage(wlMetadata, podMetadata, begginingOfPodPath) = path{
	path1 := noK8sLabelOrNoK8sLabelUsage(wlMetadata, "")
	path2 := noK8sLabelOrNoK8sLabelUsage(podMetadata, begginingOfPodPath)
	path = array.concat(path1, path2)
}

# There is label-usage for WL but not for his Pod
noK8sLabelUsage(wlMetadata, podMetadata, begginingOfPodPath) = path{
	not noK8sLabelOrNoK8sLabelUsage(wlMetadata, "")
	path := noK8sLabelOrNoK8sLabelUsage(podMetadata, begginingOfPodPath)
}

# There is no label-usage for WL but there is for his Pod
noK8sLabelUsage(wlMetadata, podMetadata, begginingOfPodPath) = path{
	not noK8sLabelOrNoK8sLabelUsage(podMetadata, begginingOfPodPath)
	path := noK8sLabelOrNoK8sLabelUsage(wlMetadata, "")
}

noK8sLabelOrNoK8sLabelUsage(metadata, begginingOfPath) = path{
	not metadata.labels
	path = [sprintf("%vmetadata", [begginingOfPath])]
}

noK8sLabelOrNoK8sLabelUsage(metadata, begginingOfPath) = path{
	labels := metadata.labels
	not allKubernetesLabels(labels)
	path = [sprintf("%vmetadata.labels", [begginingOfPath])]
}

allKubernetesLabels(labels){
	_ := labels[name]
	startswith(name, "app.kubernetes.io/")

}
