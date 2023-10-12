package armo_builtins
# Deny mutating action unless user is in group owning the resource



deny[msga] {

	pod := input[_]
	pod.kind == "Pod"
	fixPath := no_label_or_no_label_usage(pod, "")

    msga := {
		"alertMessage": sprintf("in the following pods a certain set of labels is not defined: %v", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": fixPath,
         "alertObject": {
			"k8sApiObjects": [pod]
		}
     }
}


deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	podSpec := wl.spec.template
	beggining_of_pod_path := "spec.template."
	fixPath := no_label_usage(wl, podSpec, beggining_of_pod_path)

    msga := {
		"alertMessage": sprintf("%v: %v a certain set of labels is not defined:", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": fixPath,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

# handles cronjob
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	podSpec := wl.spec.jobTemplate.spec.template
	beggining_of_pod_path := "spec.jobTemplate.spec.template."
	fixPath := no_label_usage(wl, podSpec, beggining_of_pod_path)


    msga := {
		"alertMessage": sprintf("the following cronjobs a certain set of labels is not defined: %v", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": fixPath,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

# There is no label-usage in WL and also for his Pod
no_label_usage(wl, podSpec, beggining_of_pod_path) = path{
	path1 := no_label_or_no_label_usage(wl, "")
	path2 := no_label_or_no_label_usage(podSpec, beggining_of_pod_path)
	path = array.concat(path1, path2)
}

# There is label-usage for WL but not for his Pod
no_label_usage(wl, podSpec, beggining_of_pod_path) = path{
	not no_label_or_no_label_usage(wl, "")
	path := no_label_or_no_label_usage(podSpec, beggining_of_pod_path)
}

# There is no label-usage for WL but there is for his Pod
no_label_usage(wl, podSpec, beggining_of_pod_path) = path{
	not no_label_or_no_label_usage(podSpec, beggining_of_pod_path)
	path := no_label_or_no_label_usage(wl, "")
}

no_label_or_no_label_usage(wl, start_of_path) = path{
	not wl.metadata
	label_key := get_label_key("")
	path = [{"path": sprintf("%vmetadata.labels[%v]", [start_of_path, label_key]), "value": "YOUR_VALUE"}]
}

no_label_or_no_label_usage(wl, start_of_path) = path{
	metadata := wl.metadata
	not metadata.labels
	label_key := get_label_key("")
	path = [{"path": sprintf("%vmetadata.labels[%v]", [start_of_path, label_key]), "value": "YOUR_VALUE"}]
}

no_label_or_no_label_usage(wl, start_of_path) = path{
	labels := wl.metadata.labels
	not is_desired_label(labels)
	label_key := get_label_key("")
	path = [{"path": sprintf("%vmetadata.labels[%v]", [start_of_path, label_key]), "value": "YOUR_VALUE"}]
}

is_desired_label(labels) {
	recommended_labels := data.postureControlInputs.recommendedLabels
	recommended_label := recommended_labels[_]
	labels[recommended_label]
}

# get_label_key accepts a parameter so it's not considered a rule
get_label_key(unused_param) = key {
	recommended_labels := data.postureControlInputs.recommendedLabels
    count(recommended_labels) > 0
    key := recommended_labels[0]
} else = "YOUR_LABEL"
