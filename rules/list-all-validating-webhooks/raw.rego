package armo_builtins


deny [msga] {
    admissionwebhooks := [admissionwebhook | admissionwebhook = input[_]; admissionwebhook.kind == "ValidatingWebhookConfiguration"]
    admissionwebhook := admissionwebhooks[_]

    	msga := {
		"alertMessage": sprintf("The following validating webhook configuration should be checked %v.", [admissionwebhook.metadata.name]),
		"alertScore": 6,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [admissionwebhook]
		}
	}
}