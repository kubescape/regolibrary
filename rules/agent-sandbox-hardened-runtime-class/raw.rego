# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Deny SandboxTemplate when runtimeClassName is missing or empty.
deny contains msga if {
	allowed := object.get(data.postureControlInputs, "hardenedSandboxRuntimeClasses", [])
	count(allowed) > 0
	template := input[_]
	template.kind in {"Sandbox", "SandboxTemplate"}

	runtime_class := object.get(template, ["spec", "podTemplate", "spec", "runtimeClassName"], "")

	runtime_class == ""

	msga := {
		"alertMessage": sprintf("%s '%v' does not define runtimeClassName.", [template.kind, template.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.podTemplate.spec.runtimeClassName"],
		"reviewPaths": runtime_class_review_paths(template),
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

# Deny SandboxTemplate when runtimeClassName is not in the approved list.
deny contains msga if {
	allowed := object.get(data.postureControlInputs, "hardenedSandboxRuntimeClasses", [])
	count(allowed) > 0
	template := input[_]
	template.kind in {"Sandbox", "SandboxTemplate"}

	runtime_class := object.get(template, ["spec", "podTemplate", "spec", "runtimeClassName"], "")

	runtime_class != ""
	not runtime_class in allowed

	msga := {
		"alertMessage": sprintf("%s '%v' uses runtimeClassName '%v', which is not in the approved hardened runtime list.", [template.kind, template.metadata.name, runtime_class]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.podTemplate.spec.runtimeClassName"],
		"reviewPaths": ["spec.podTemplate.spec.runtimeClassName"],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

# runtimeClassName when it is set, even to "", otherwise its deepest parent
# that exists, so the evidence points at a field that is there.
runtime_class_review_paths(template) := ["spec.podTemplate.spec.runtimeClassName"] if {
	_ = template.spec.podTemplate.spec.runtimeClassName
} else := ["spec.podTemplate.spec"] if {
	is_object(template.spec.podTemplate.spec)
} else := ["spec.podTemplate"] if {
	is_object(template.spec.podTemplate)
} else := ["spec"] if {
	is_object(template.spec)
} else := []
