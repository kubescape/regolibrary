package armo_builtins
import data.kubernetes.api.client as client

	deny[msga] {
		pods_resource := client.query_all_no_auth("pods")
		pod := pods_resource.status
		pod == "200 OK"
		output :="Anonymous requests are allowed"
		msga := {
			"alertMessage": sprintf("%v", [output]),
			"alertScore": 2,
			"failedPaths": [""],
			"packagename": "armo_builtins",
			"alertObject": {
			},
		}
	}