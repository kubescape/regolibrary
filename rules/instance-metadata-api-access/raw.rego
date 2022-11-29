package armo_builtins


deny[msg] {
	obj = input[_]
	is_cloud_provider_info(obj)

	obj.data.providerMetaDataAPIAccess == true


	msg := {
		"alertMessage": sprintf("Node '%s' has access to Instance Metadata Services of cloud provider.", [obj.metadata.name]),
		"alert": true,
		"alertScore": 1,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"externalObjects": obj
		},
		"packagename": "armo_builtins"
	}

}



is_cloud_provider_info(obj) {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "cloudProviderInfo"
}