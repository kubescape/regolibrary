package armo_builtins

# deny if default ServiceAccount automountServiceAccountToken is set to true
deny [msga]{

    sa := input[_]
	sa.kind == "ServiceAccount"
	sa.metadata.name == "default"
	sa.automountServiceAccountToken == true

    msga := {
	    "alertMessage": "Default ServiceAccount automountServiceAccountToken is set to True",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": ["automountServiceAccountToken: true"],
		"fixPaths": [{"path": "automountServiceAccountToken",  "value": "false"}],
		"alertObject": {
			"k8sApiObjects": [sa]
		}
	}
}    
