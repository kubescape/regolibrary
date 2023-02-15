package armo_builtins

deny[msga] {
    resource := input[_]
	resource.kind == "Role"

	msga := {
		"alertMessage": sprintf("For namespace '%v', make sure Kubernetes RBAC users are managed with AWS IAM Authenticator for Kubernetes or Upgrade to AWS CLI v1.16.156", [resource.metadata.namespace]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"externalObjects": resource
		}
	}
}
