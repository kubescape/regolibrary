package armo_builtins
import future.keywords.every

# Fails if namespace does not have relevant labels and no 3rd party security admission exists
deny[msga] {
	namespace := input[_]
	namespace.kind == "Namespace"
	not restricted_admission_policy_enabled(namespace)
    not has_external_policy_control(input)

	msga := {
		"alertMessage": sprintf("Namespace: %v does not enable restricted pod security admission", [namespace.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [namespace]
		}
	}
}

# Fails if at least 1 namespace does not have relevant labels and 3rd party security admission EXISTS
# returns webhook configuration for user to review
deny[msga] {
	some namespace in input
	namespace.kind == "Namespace"
	not restricted_admission_policy_enabled(namespace)

    admissionwebhook := input[_]
    admissionwebhook.kind in ["ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"]
    admissionwebhook.webhooks[i].rules[j].scope != "Cluster"

	msga := {
		"alertMessage": sprintf("Review webhook: %v ensure that it defines the required policy", [admissionwebhook.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [admissionwebhook]
		}
	}
}

restricted_admission_policy_enabled(namespace){
	some key, value in namespace.metadata.labels 
    key == "pod-security.kubernetes.io/enforce"
	value ==  "restricted"
}

has_external_policy_control(inp){
    some admissionwebhook in inp
    admissionwebhook.kind in ["ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"]
    admissionwebhook.webhooks[i].rules[j].scope != "Cluster"
}