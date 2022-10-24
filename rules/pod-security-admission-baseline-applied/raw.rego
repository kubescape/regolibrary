package armo_builtins
import future.keywords.in

# Fails if namespace does not have relevant labels and no 3rd party security admission exists
deny[msga] {
	namespace := input[_]
	namespace.kind == "Namespace"
	not baseline_admission_policy_enabled(namespace)
    not has_external_policy_control(input)

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

    admissionwebhook := has_external_policy_control(input)

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
	namespace.metadata.labels["pod-security.kubernetes.io/enforce"]  in ["baseline", "restricted"]
}

has_external_policy_control(inp) = admissionwebhook{
    some admissionwebhook in inp
    admissionwebhook.kind in ["ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"]
    admissionwebhook.webhooks[i].rules[j].scope != "Cluster"
}