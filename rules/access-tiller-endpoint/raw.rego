package armo_builtins

# input: deployment
# fails if tiller exists in cluster

deny[msga] {
	deployment := 	input[_]
	deployment.kind == "Deployment"
    deployment.metadata.name == "tiller-deploy"

	msga := {
		"alertMessage": sprintf("tiller exists in namespace: %v", [deployment.metadata.namespace]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [deployment]
		}
	}
}