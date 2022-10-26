package armo_builtins
import future.keywords.in

# if no 3rd party security admission exists - Fails if namespace does not have relevant labels
deny[msga] {
    not has_external_policy_control(input)
	namespace := input[_]
	namespace.kind == "Namespace"

	msga := {
		"alertMessage": sprintf("Namespace: %v does not enable baseline pod security admission", [namespace.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [namespace]
		}
	}
}

# Fails if at least 1 namespace does not have relevant labels and 3rd party namespaced security admission EXISTS
# returns webhook configuration for user to review
deny[msga] {
	some namespace in input
	namespace.kind == "Namespace"
	not baseline_admission_policy_enabled(namespace)

    admissionwebhook := input[_]
    admissionwebhook.kind in ["ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"]

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


baseline_admission_policy_enabled(namespace){
	some key, value in namespace.metadata.labels 
    key == "pod-security.kubernetes.io/enforce"
	value in ["baseline", "restricted"]
}

has_external_policy_control(inp){
    some admissionwebhook in inp
    admissionwebhook.kind in ["ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"]
    admissionwebhook.webhooks[i].rules[j].scope != "Cluster"
}