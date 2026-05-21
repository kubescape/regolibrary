package armo_builtins

import rego.v1

deny contains msga if {
	mutatingwebhooks := [mutatingwebhook | mutatingwebhook = input[_]; mutatingwebhook.kind == "MutatingWebhookConfiguration"]
	mutatingwebhook := mutatingwebhooks[_]

	msga := {
		"alertMessage": sprintf("The following mutating webhook configuration should be checked %v.", [mutatingwebhook.metadata.name]),
		"alertScore": 6,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [mutatingwebhook]},
	}
}
