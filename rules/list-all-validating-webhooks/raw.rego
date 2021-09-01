package armo_builtins
import data.cautils as cautils


deny [msga] {
    admissionwebhooks := [admissionwebhook | admissionwebhook = input[_]; admissionwebhook.kind == "ValidatingWebhookConfiguration"]
    admissionwebhook := admissionwebhooks[_]

    	msga := {
		"alertMessage": sprintf("the following validating webhook configuration should be checked %v.", [admissionwebhook]),
		"alertScore": 6,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [admissionwebhook]
		}
	}


}