package armo_builtins

# input: network policies + namespaces
# apiversion: networking.k8s.io/v1
# returns all namespaces

deny[msga] {
	namespaces := [namespace | namespace = input[_]; namespace.kind == "Namespace"]
	namespace := namespaces[_]

	msga := {
		"alertMessage": sprintf("no policy is defined for namespace %v", [namespace.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [namespace]
		}
	}
}