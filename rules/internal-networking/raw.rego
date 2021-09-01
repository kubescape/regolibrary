package armo_builtins

# input: network policies
# apiversion: networking.k8s.io/v1
# fails if no network policies are defined in a certain namespace

deny[msga] {
	namespaces := [namespace | namespace = input[_]; namespace.kind == "Namespace"]
	namespace := namespaces[_]
	policy_names := [policy.metadata.namespace | policy = input[_]; policy.kind == "NetworkPolicy"]
	not list_contains(policy_names, namespace.metadata.name)

	msga := {
		"alertMessage": sprintf("no policy is defined for namespace %v", [namespace.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [namespace]
		}
	}
}

list_contains(list, element) {
  some i
  list[i] == element
}