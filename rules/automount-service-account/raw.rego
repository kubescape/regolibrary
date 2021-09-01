package armo_builtins

# Fails if user account mount tokens in pod by default.
deny [msga]{
    serviceaccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceaccounts[_]
    isAutoMount(serviceaccount)

    msga := {
	    "alertMessage": sprintf("the following service account: %v in the following namespace: %v mounts service account tokens in pods by default", [serviceaccount.metadata.name, serviceaccount.metadata.namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [serviceaccount]
		}
	}
}    

isAutoMount(serviceaccount) {
	not serviceaccount.automountServiceAccountToken == false
}