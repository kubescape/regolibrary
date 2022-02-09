package armo_builtins

# input: network policies
# apiversion: networking.k8s.io/v1
# fails if no network policies are defined

deny[msga] {
	networkpolicies := input
    count(networkpolicies) == 0

	msga := {
		"alertMessage": "no network policy is defined",
		"alertScore": 9,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			
		}
	}
}