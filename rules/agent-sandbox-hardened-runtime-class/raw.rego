# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Deny SandboxTemplate when runtimeClassName is missing or empty.
deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	runtime_class := object.get(template, ["spec", "podTemplate", "spec", "runtimeClassName"], "")

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

	runtime_class := object.get(template, ["spec", "podTemplate", "spec", "runtimeClassName"], "")

	runtime_class != ""
	not runtime_class in data.postureControlInputs.hardenedSandboxRuntimeClasses

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
