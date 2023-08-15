package armo_builtins

untrustedImageRepo[msga] {
	wl := input[_]
	containers_path := get_containers_path(wl)
	containers := object.get(wl, containers_path, [])
	container := containers[i]
	name := image.parse_normalized_name(container.image)
	untrusted_or_public_registries(name)
	path := sprintf("%s[%d].image", [concat(".", containers_path), i])

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

untrusted_or_public_registries(image){
	# see default-config-inputs.json for list values
	untrusted_registries := data.postureControlInputs.untrustedRegistries
	registry := untrusted_registries[_]
	startswith(image, registry)

}

untrusted_or_public_registries(image){
	# see default-config-inputs.json for list values
	public_registries := data.postureControlInputs.publicRegistries
	registry := public_registries[_]
	startswith(image, registry)
}

# get_containers_path - get resource containers paths for  {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_containers_path(resource) := result {
	resource_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	resource_kinds[resource.kind]
	result = ["spec", "template", "spec", "containers"]
}

# get_containers_path - get resource containers paths for "Pod"
get_containers_path(resource) := result {
	resource.kind == "Pod"
	result = ["spec", "containers"]
}

# get_containers_path - get resource containers paths for  "CronJob"
get_containers_path(resource) := result {
	resource.kind == "CronJob"
	result = ["spec", "jobTemplate", "spec", "template", "spec", "containers"]
}