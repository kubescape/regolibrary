package armo_builtins
# Check for images from blacklisted repos

metadata_azure(z) = http.send({
	"url": "http://169.254.169.254/metadata/instance?api-version=2020-09-01",
	"method": "get",
	"headers": {"Metadata": "true"},
	"raise_error": true,	
})

metadata_gcp(z) = http.send({
	"url": "http://169.254.169.254/computeMetadata/v1/?alt=json&recursive=true",
	"method": "get",
	"headers": {"Metadata-Flavor": "Google"},
	"raise_error": true,	
})

metadata_aws(z) = metadata_object { 
	hostname := http.send({
	"url": "http://169.254.169.254/latest/meta-data/local-hostname",
	"method": "get",
	"raise_error": true,	
    })
	metadata_object := {
		"raw_body": hostname.raw_body,
		"hostname" : hostname.raw_body,
		"status_code" : hostname.status_code
	}
}

azure_metadata[msga] {	
	metadata_object := metadata_azure("aaa")
	metadata_object.status_code == 200
	node_name := metadata_object.body.compute.name
	nodes := input[_]
	nodes.metadata.name == node_name
	msga := {
		"alertMessage": sprintf("Node '%s' has access to Instance Metadata Services of Azure.", [node_name]),
		"alert": true,
		"prevent": false,
		"alertScore": 1,
		"alertObject": {
			"k8SApiObjects": [nodes],
			"externalObjects": {
				"azureMetadata" : [metadata_object.body]
			}
		}
	}
}

gcp_metadata[msga] {	
	metadata_object := metadata_gcp("aaa")
	metadata_object.status_code == 200
	node_name := metadata_object.body.instance.hostname
	nodes := input[_]
	nodes.metadata.name == node_name
	msga := {
		"alertMessage": sprintf("Node '%s' has access to Instance Metadata Services of GCP.", [node_name]),
		"alert": true,
		"prevent": false,
		"alertScore": 1,
		"alertObject": {
			"k8SApiObjects": [nodes],
			"externalObjects": {
				"gcpMetadata" : [metadata_object.raw_body]
			}
		}
	}
}

aws_metadata[msga] {	
	metadata_object := metadata_aws("aaa")
	metadata_object.status_code == 200
	node_name := metadata_object.hostname
	nodes := input[_]
	nodes.metadata.name == node_name
	msga := {
		"alertMessage": sprintf("Node '%s' has access to Instance Metadata Services of AWS.", [node_name]),
		"alert": true,
		"prevent": false,
		"alertScore": 1,
		"alertObject": {
			"k8SApiObjects": [nodes],
			"externalObjects": {
				"awsMetadata" : [metadata_object.raw_body]
			}
		}
	}
}