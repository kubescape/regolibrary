package armo_builtins

# input: service accounts
# apiversion: v1 
# returns ImagePullSecrets that more than one service account have access to

deny[msga] {

    image = input[i].imagePullSecrets[_] == input[j].imagePullSecrets[_]
	i > j

	msga := {
		"alertMessage": sprintf("the following ImagePullSecret: %v, is exposed to more than one serviceaccount", [image]),
		"alertScore": 9,
		"packagename": "armo_builtins",
	   "alertObject": {
		}
	}
}