package armo_builtins
import data.cautils as cautils


deny [msga] {
    mutatingwebhooks := [mutatingwebhook | mutatingwebhook = input[_]; mutatingwebhook.kind == "MutatingWebhookConfiguration"]
    mutatingwebhook := mutatingwebhooks[_]

    	msga := {
		"alertMessage": sprintf("the following mutating webhook configuration should be checked %v.", [mutatingwebhook]),
		"alertScore": 6,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [mutatingwebhook]
		}
	}
}