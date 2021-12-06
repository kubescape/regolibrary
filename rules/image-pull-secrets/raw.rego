package armo_builtins

# input: service accounts
# apiversion: v1 
# returns ImagePullSecrets that more than one service account have access to

deny[msga] {

    image = input[i].imagePullSecrets[k] == input[j].imagePullSecrets[_]
	path := sprintf("imagePullSecrets[%v]", [format_int(k, 10)])
	i > j

	msga := {
		"alertMessage": sprintf("the following ImagePullSecret: %v, is exposed to more than one serviceaccount", [image]),
		"alertScore": 9,
		"failedPaths": [path],
		"packagename": "armo_builtins",
	   "alertObject": {
		}
	}
}