# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Deny SandboxTemplate when runtimeClassName is missing or empty.
deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	path_to_runtime_class := ["spec", "podTemplate", "spec", "runtimeClassName"]
	runtime_class := object.get(template, path_to_runtime_class, "")

	runtime_class == ""

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' does not define runtimeClassName.", [template.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.podTemplate.spec.runtimeClassName"],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [template],
		},
	}
}

# Deny SandboxTemplate when runtimeClassName is not in the approved list.
deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	# see default-config-inputs.json for list values
	hardened_runtimes := data.postureControlInputs.hardenedSandboxRuntimeClasses

	path_to_runtime_class := ["spec", "podTemplate", "spec", "runtimeClassName"]
	runtime_class := object.get(template, path_to_runtime_class, "")

	runtime_class != ""
	not runtime_class_allowed(runtime_class, hardened_runtimes)

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' uses runtimeClassName '%v', which is not in the approved hardened runtime list.", [template.metadata.name, runtime_class]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.podTemplate.spec.runtimeClassName"],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [template],
		},
	}
}

runtime_class_allowed(runtime_class, allowed_list) if {
	runtime_class == allowed_list[_]
}

