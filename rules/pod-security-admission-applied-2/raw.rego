package armo_builtins

import rego.v1

# Fails if no 3rd party security admission exists and namespace does not have relevant labels
deny contains msga if {
	not has_external_policy_control(input)
	namespace := input[_]
	namespace.kind == "Namespace"
	not admission_policy_enabled(namespace)
	fix_path = {"path": "metadata.labels[pod-security.kubernetes.io/enforce]", "value": "YOUR_VALUE"}

	msga := {
		"alertMessage": sprintf("Namespace: %v does not enable pod security admission", [namespace.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [fix_path],
		"alertObject": {"k8sApiObjects": [namespace]},
	}
}

admission_policy_enabled(namespace) if {
	some label, _ in namespace.metadata.labels
	startswith(label, "pod-security.kubernetes.io/enforce")
}

has_external_policy_control(inp) if {
	admissionwebhook := inp[_]
	admissionwebhook.kind in ["ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"]
	admissionwebhook.webhooks[i].rules[j].scope != "Cluster"
}
