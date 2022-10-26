package armo_builtins
import future.keywords.every

# Fails if no 3rd party security admission exists and namespace does not have relevant labels
deny[msga] {
    not has_external_policy_control(input)
	namespace := input[_]
	namespace.kind == "Namespace"
	not admission_policy_enabled(namespace)
	
    

	msga := {
		"alertMessage": sprintf("Namespace: %v does not enable pod security admission", [namespace.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [namespace]
		}
	}
}

admission_policy_enabled(namespace){
	some label, _ in namespace.metadata.labels 
    startswith(label, "pod-security.kubernetes.io/")
}

has_external_policy_control(inp){
    admissionwebhook := inp[_]
    admissionwebhook.kind in ["ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"]
    admissionwebhook.webhooks[i].rules[j].scope != "Cluster"
}