
package armo_builtins

# fails in case authorizedIPRanges is not set.
deny[msga] {
	obj := input[_]
	obj.apiVersion == "management.azure.com/v1"
	obj.kind == "ClusterDescribe"
	obj.metadata.provider == "aks"
	config = obj.data

	not isAuthorizedIPRangesSet(config)

	msga := {
    	"alertMessage": "Parameter 'authorizedIPRanges' was not set.",
    	"packagename": "armo_builtins",
    	"alertScore": 7,
    	"failedPaths": [""],
    	"fixPaths":[],
        "fixCommand": "az aks update -n '<name>' -g '<resource_group>' --api-server-authorized-ip-ranges '0.0.0.0/32'",
    	"alertObject": {
			"externalObjects": obj
        }
    }

}

isAuthorizedIPRangesSet(config) {
	count(config.properties.apiServerAccessProfile.authorizedIPRanges) > 0
}
