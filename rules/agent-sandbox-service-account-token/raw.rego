# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# A directly created Sandbox does not pass through the SandboxTemplate secure
# default, so it must disable token automount explicitly.
deny contains msga if {
	sandbox := input[_]
	sandbox.kind == "Sandbox"

	automount := object.get(sandbox, ["spec", "podTemplate", "spec", "automountServiceAccountToken"], null)
	automount != false

	msga := {
		"alertMessage": sprintf("Sandbox '%v' must set automountServiceAccountToken to false; direct Sandbox resources do not receive the SandboxTemplate secure default.", [resource_name(sandbox)]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.podTemplate.spec.automountServiceAccountToken"],
		"reviewPaths": ["spec.podTemplate.spec.automountServiceAccountToken"],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [sandbox]},
	}
}

# SandboxTemplate processing defaults an omitted value to false. Only an
# explicit true opts out of that protection and should fail posture checks.
deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	automount := object.get(template, ["spec", "podTemplate", "spec", "automountServiceAccountToken"], false)
	automount == true

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' explicitly enables service account token automounting; omit the field or set it to false.", [resource_name(template)]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.podTemplate.spec.automountServiceAccountToken"],
		"reviewPaths": ["spec.podTemplate.spec.automountServiceAccountToken"],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

resource_name(resource) := object.get(resource, ["metadata", "name"], "<unnamed>")
