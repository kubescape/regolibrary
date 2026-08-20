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
	_is_non_compliant_image(image)

	path := sprintf("spec.podTemplate.spec.containers[%d].image", [i])

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' container '%v' uses image '%v' which is untagged, uses the mutable ':latest' tag, or uses a configured floating tag. Pin to an explicit version tag or digest.", [object.get(template, ["metadata", "name"], "<unnamed>"), object.get(container, "name", "<unnamed>"), image]),
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
	_is_non_compliant_image(image)

	path := sprintf("spec.podTemplate.spec.initContainers[%d].image", [i])

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' initContainer '%v' uses image '%v' which is untagged, uses the mutable ':latest' tag, or uses a configured floating tag. Pin to an explicit version tag or digest.", [object.get(template, ["metadata", "name"], "<unnamed>"), object.get(container, "name", "<unnamed>"), image]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

_is_non_compliant_image(image) if {
	_is_latest_or_untagged(image)
}

_is_non_compliant_image(image) if {
	_is_floating_image_tag(image)
}

_is_latest_or_untagged(image) if {
	not _has_digest(image)
	not _has_explicit_non_latest_tag(image)
}

_is_floating_image_tag(image) if {
	not contains(image, "@")
	parts := split(image, "/")
	last := parts[count(parts) - 1]
	tag_parts := split(last, ":")
	count(tag_parts) == 2
	tag := tag_parts[1]
	tag in data.postureControlInputs.floatingImageTags
}

_has_digest(image) if {
	contains(image, "@")
}

_has_explicit_non_latest_tag(image) if {
	not contains(image, "@")
	parts := split(image, "/")
	last := parts[count(parts) - 1]
	tag_parts := split(last, ":")
	count(tag_parts) == 2
	tag_parts[1] != "latest"
}
