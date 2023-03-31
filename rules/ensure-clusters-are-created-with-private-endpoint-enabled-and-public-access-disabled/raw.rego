
package armo_builtins

# fails in case privateEndpoint.id parameter is not found on ClusterDescribe
deny[msga] {
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
    	"failedPaths": [""],
    	"fixPaths":[],
        "fixCommand": "",
    	"alertObject": {
			"externalObject": [obj]
        }
    }
}

isPrivateEndpointEnabled(config) {
	config.properties.privateEndpoint.id
}