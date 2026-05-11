package armo_builtins
import future.keywords.in

# Fails if namespace does not have baseline pod security admission label
deny[msga] {
	namespace := input[_]
	namespace.kind == "Namespace"
	not baseline_admission_policy_enabled(namespace)

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

baseline_admission_policy_enabled(namespace){
	some key, value in namespace.metadata.labels
    key == "pod-security.kubernetes.io/enforce"
	value in ["baseline", "restricted"]
}