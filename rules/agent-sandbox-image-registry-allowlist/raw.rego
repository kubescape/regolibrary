# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	containers := object.get(template, ["spec", "podTemplate", "spec", "containers"], [])
	container := containers[i]

	image := object.get(container, "image", "")
	image != ""
	not _image_in_allowed_list(image)

	path := sprintf("spec.podTemplate.spec.containers[%d].image", [i])

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' container '%v' uses image '%v' from a registry not in the allowed list.", [object.get(template, ["metadata", "name"], "<unnamed>"), object.get(container, "name", "<unnamed>"), image]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	init_containers := object.get(template, ["spec", "podTemplate", "spec", "initContainers"], [])
	container := init_containers[i]

	image := object.get(container, "image", "")
	image != ""
	not _image_in_allowed_list(image)

	path := sprintf("spec.podTemplate.spec.initContainers[%d].image", [i])

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' initContainer '%v' uses image '%v' from a registry not in the allowed list.", [object.get(template, ["metadata", "name"], "<unnamed>"), object.get(container, "name", "<unnamed>"), image]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

_image_in_allowed_list(image) if {
	allowedlist := data.postureControlInputs.imageRepositoryAllowList
	registry := allowedlist[_]
	regex.match(_regexify(registry), _docker_host_wrapper(image))
}

_docker_host_wrapper(image) := result if {
	not contains(image, "/")
	result := sprintf("docker.io/%s", [image])
} else := image

_regexify(registry) := result if {
	endswith(registry, "/")
	result = sprintf("^%s.*$", [registry])
} else := sprintf("^%s\\/.*$", [registry])
