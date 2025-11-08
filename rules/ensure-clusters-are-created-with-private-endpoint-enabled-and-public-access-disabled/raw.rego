package armo_builtins

import rego.v1

# fails in case privateEndpoint.id parameter is not found on ClusterDescribe
deny contains msga if {
	obj := input[_]
	obj.apiVersion == "management.azure.com/v1"
	obj.kind == "ClusterDescribe"
	obj.metadata.provider == "aks"
	config = obj.data

	not isPrivateEndpointEnabled(config)

	msga := {
		"alertMessage": "Private endpoint not enabled.",
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "",
		"alertObject": {"externalObjects": obj},
	}
}

isPrivateEndpointEnabled(config) if {
	config.properties.privateEndpoint.id
}
