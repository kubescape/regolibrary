package armo_builtins

deny[msga] {
	resource := input[_]
	volumes_path := get_volumes_path(resource)
	volumes := object.get(resource, volumes_path, [])
	volume := volumes[i]
	volume.secret

	secret := input[_]
	secret.kind == "Secret"
	secret.metadata.name == volume.secret.secretName
	is_same_namespace(secret.metadata, resource.metadata)

	# add related ressource
	resource_vector := json.patch(resource, [{"op": "add", "path": "relatedObjects", "value": [secret]}])

	failedPaths := sprintf("%s[%d].secret", [concat(".", volumes_path), i])

	msga := {
		"alertMessage": sprintf("%v: %v has mounted secret", [resource.kind, resource.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [failedPaths],
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [resource],
			"externalObjects": resource_vector
		}
	}
}

# get_volume_path - get resource volumes paths for {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_volumes_path(resource) := result {
	resource_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	resource_kinds[resource.kind]
	result = ["spec", "template", "spec", "volumes"]
}

# get_volumes_path - get resource volumes paths for "Pod"
get_volumes_path(resource) := result {
	resource.kind == "Pod"
	result = ["spec", "volumes"]
}

# get_volumes_path - get resource volumes paths for "CronJob"
get_volumes_path(resource) := result {
	resource.kind == "CronJob"
	result = ["spec", "jobTemplate", "spec", "template", "spec", "volumes"]
}



is_same_namespace(metadata1, metadata2) {
	metadata1.namespace == metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
	not metadata1.namespace
	not metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
	not metadata2.namespace
	metadata1.namespace == "default"
}

is_same_namespace(metadata1, metadata2) {
	not metadata1.namespace
	metadata2.namespace == "default"
}