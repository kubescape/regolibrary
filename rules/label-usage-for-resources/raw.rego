package armo_builtins
# Deny mutating action unless user is in group owning the resource



deny[msga] {

	pod := input[_]
	pod.kind == "Pod"
	metadata := pod.metadata
	path := noLabelOrNoLabelUsage(metadata, "")

    msga := {
		"alertMessage": sprintf("in the following pods a certain set of labels is not defined: %v", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
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
	path := noLabelUsage(wlMetadata, podMetadata, begginingOfPodPath)

    msga := {
		"alertMessage": sprintf("%v: %v a certain set of labels is not defined:", [wl.kind, wl.metadata.name]),
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
	path := noLabelUsage(wlMetadata, podMetadata, begginingOfPodPath)


    msga := {
		"alertMessage": sprintf("the following cronjobs a certain set of labels is not defined: %v", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 0,
		"failedPaths": path,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}


# There is no label-usage in WL and also for his Pod
noLabelUsage(wlMetadata, podMetadata, begginingOfPodPath) = path{
	path1 := noLabelOrNoLabelUsage(wlMetadata, "")
	path2 := noLabelOrNoLabelUsage(podMetadata, begginingOfPodPath)
	path = array.concat(path1, path2)
}

# There is label-usage for WL but not for his Pod
noLabelUsage(wlMetadata, podMetadata, begginingOfPodPath) = path{
	not noLabelOrNoLabelUsage(wlMetadata, "")
	path := noLabelOrNoLabelUsage(podMetadata, begginingOfPodPath)
}

# There is no label-usage for WL but there is for his Pod
noLabelUsage(wlMetadata, podMetadata, begginingOfPodPath) = path{
	not noLabelOrNoLabelUsage(podMetadata, begginingOfPodPath)
	path := noLabelOrNoLabelUsage(wlMetadata, "")
}

noLabelOrNoLabelUsage(metadata, begginingOfPath) = path{
	not metadata.labels
	path = [sprintf("%vmetadata", [begginingOfPath])]
}

noLabelOrNoLabelUsage(metadata, begginingOfPath) = path{
	labels := metadata.labels
	not isDesiredLabel(labels)
	path = [sprintf("%vmetadata.labels", [begginingOfPath])]
}

isDesiredLabel(labels) {
	_ = labels.app
}

isDesiredLabel(labels) {
	_ = labels.tier
}

isDesiredLabel(labels) {
	_ = labels.phase
}

isDesiredLabel(labels) {
	_ = labels.version
}

isDesiredLabel(labels){
	_ = labels.owner
}

isDesiredLabel(labels) {
	_ = labels.env
}