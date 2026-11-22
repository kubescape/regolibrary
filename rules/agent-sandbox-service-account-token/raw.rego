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
		"reviewPaths": automount_review_paths(sandbox),
		"fixPaths": automount_fix_paths(sandbox),
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

# The field when the Sandbox sets it, otherwise its deepest parent that exists,
# so the evidence points at a field that is there.
automount_review_paths(sandbox) := ["spec.podTemplate.spec.automountServiceAccountToken"] if {
	_ = sandbox.spec.podTemplate.spec.automountServiceAccountToken
} else := ["spec.podTemplate.spec"] if {
	is_object(sandbox.spec.podTemplate.spec)
} else := ["spec.podTemplate"] if {
	is_object(sandbox.spec.podTemplate)
} else := ["spec"] if {
	is_object(sandbox.spec)
} else := []

# An omitted field is added as false. One that is set is left to the reviewer.
automount_fix_paths(sandbox) := [] if {
	_ = sandbox.spec.podTemplate.spec.automountServiceAccountToken
} else := [{"path": "spec.podTemplate.spec.automountServiceAccountToken", "value": "false"}]
