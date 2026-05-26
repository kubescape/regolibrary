package armo_builtins
import future.keywords.every

# Fails if namespace does not have restricted pod security admission label
deny[msga] {
	namespace := input[_]
	namespace.kind == "Namespace"
	not restricted_admission_policy_enabled(namespace)

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

restricted_admission_policy_enabled(namespace){
	namespace.metadata.labels["pod-security.kubernetes.io/enforce"] == "restricted"
}