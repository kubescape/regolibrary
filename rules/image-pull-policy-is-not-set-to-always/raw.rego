package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
    is_bad_container(container)
	paths = [sprintf("spec.containers[%v].image", [format_int(i, 10)]), sprintf("spec.containers[%v].imagePullPolicy", [format_int(i, 10)])]
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  has 'latest' tag on image but imagePullPolicy is not set to 'Always'", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"reviewPaths": paths,
		"failedPaths": paths,
		"fixPaths":[],
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
	paths = [sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)]), sprintf("spec.template.spec.containers[%v].imagePullPolicy", [format_int(i, 10)])]
    is_bad_container(container)
	msga := {
		"alertMessage": sprintf("container: %v in %v: %v  has 'latest' tag on image but imagePullPolicy is not set to 'Always'", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"reviewPaths": paths,
		"failedPaths": paths,
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	paths = [sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [format_int(i, 10)]), sprintf("spec.jobTemplate.spec.template.spec.containers[%v].imagePullPolicy", [format_int(i, 10)])]
    is_bad_container(container)
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  has 'latest' tag on image but imagePullPolicy is not set to 'Always'", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"reviewPaths": paths,
		"failedPaths": paths,
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# image tag is latest
is_bad_container(container){
    reg := ":[\\w][\\w.-]{0,127}(\/)?"
    version := regex.find_all_string_submatch_n(reg, container.image, -1)
    v := version[_]
    img := v[_]
    img == ":latest"
    not_image_pull_policy(container)
}

# No image tag or digest (== latest)
is_bad_container(container){
    not is_tag_image(container.image)
    not_image_pull_policy(container)
}

# image tag is only letters (== latest)
is_bad_container(container){
    is_tag_image_only_letters(container.image)
    not_image_pull_policy(container)
}

not_image_pull_policy(container) {
     container.imagePullPolicy == "Never"
}


not_image_pull_policy(container) {
     container.imagePullPolicy == "IfNotPresent"
}

is_tag_image(image) {
    reg := ":[\\w][\\w.-]{0,127}(\/)?"
    version := regex.find_all_string_submatch_n(reg, image, -1)
    v := version[_]
    img := v[_]
    not endswith(img, "/")
}

# The image has a tag, and contains only letters
is_tag_image_only_letters(image) {
    reg := ":[\\w][\\w.-]{0,127}(\/)?"
    version := regex.find_all_string_submatch_n(reg, image, -1)
    v := version[_]
    img := v[_]
	reg1 := "^:[a-zA-Z]{1,127}$"
	re_match(reg1, img)
}
