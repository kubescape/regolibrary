package armo_builtins
import data.kubernetes.api.client as client
import data
import future.keywords.in


# deny workloads that doesn't support external service provider (secretProviderClass)
# reference - https://secrets-store-csi-driver.sigs.k8s.io/concepts.html
deny[msga] {

    resources := input[_]

	# get volume paths for each resource
	volumes_path := get_volumes_path(resources)

	# get volumes for each resources
	volumes := object.get(resources, volumes_path, [])

	# continue if secretProviderClass not found in resource
	having_secretProviderClass := {i | volumes[i].csi.volumeAttributes.secretProviderClass}
  	count(having_secretProviderClass) == 0


	# prepare message data.
	alert_message :=  sprintf("%s: %v is not using external secret storage", [resources.kind, resources.metadata.name])
	failed_paths := []
	fixed_paths := [{"path":sprintf("%s[0].csi.volumeAttributes.secretProviderClass",[concat(".", volumes_path)]), "value":"YOUR_VALUE"}]

	msga := {
		"alertMessage": alert_message,
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_paths,
		"fixPaths": fixed_paths,
		"alertObject": {
			"k8sApiObjects": [resources]
		}
	}
}


# get_volume_path - get resource volumes paths for {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_volumes_path(resources) := result {
	resources_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	resources_kinds[resources.kind]
	result = ["spec", "template", "spec", "volumes"]
}

# get_volumes_path - get resource volumes paths for "Pod"
get_volumes_path(resources) := result {
	resources.kind == "Pod"
	result = ["spec", "volumes"]
}

# get_volumes_path - get resource volumes paths for "CronJob"
get_volumes_path(resources) := result {
	resources.kind == "CronJob"
	result = ["spec", "jobTemplate", "spec", "template", "spec", "volumes"]
}
