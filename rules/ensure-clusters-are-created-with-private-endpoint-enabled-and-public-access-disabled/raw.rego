
package armo_builtins

# fails in case enablePrivateCluster is set to false.
deny[msga] {
	obj := input[_]
	obj.apiVersion == "management.azure.com/v1"
	obj.kind == "ClusterDescribe"
	obj.metadata.provider == "aks"
	config = obj.data

	not isPrivateClusterEnabled(config)

	msga := {
    	"alertMessage": "AKS private enpoint is not enabled.",
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

isPrivateClusterEnabled(config) {
	config.properties.apiServerAccessProfile.enablePrivateCluster == true
}
