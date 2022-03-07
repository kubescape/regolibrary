package armo_builtins
import data.kubernetes.api.client as client

# Both config and cli present
deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"
		kubeletCliData := kubeletCli.data


		isClientTlsDisabledBoth(kubeletConfig, kubeletCliData)


		msga := {
			"alertMessage": "kubelet client TLS authentication is not enabled",
			"alertScore": 2,
			"failedPaths": [],
			"fixPaths":[],
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [kubeletConfig, kubeletCli]
			},
		}
	}


# Only of them present
deny[msga] {
		externalObj := isClientTlsDisabledSingle(input)

		msga := {
			"alertMessage": "kubelet client TLS authentication is not enabled",
			"alertScore": 2,
			"failedPaths": [],
			"fixPaths":[],
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [externalObj]
			},
		}
	}

# CLI overrides config
isClientTlsDisabledBoth(kubeletConfig, kubeletCliData) {
	not contains(kubeletCliData["fullCommand"], "client-ca-file")
    not kubeletConfig.data.authentication.x509.clientCAFile
}

# Only cli
isClientTlsDisabledSingle(resources) = obj {
	kubeletCli := resources[_]            
	kubeletCli.kind == "KubeletCommandLine"
	kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletConfig := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubeletConfig) == 0

	obj = isClientTlsDisabledCli(kubeletCli)
	
}

# Only config
isClientTlsDisabledSingle(resources) = obj {
	kubeletConfig := resources[_]            
	kubeletConfig.kind == "KubeletConfiguration"
	kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletCmd := [cmd | cmd = resources[_]; cmd.kind == "KubeletCommandLine"]
	count(kubeletCmd) == 0

	obj = isClientTlsDisabledConfig(kubeletConfig)
}


isClientTlsDisabledConfig(kubeletConfig) = obj {
	not kubeletConfig.data.authentication.x509.clientCAFile
	obj = kubeletConfig
}

isClientTlsDisabledCli(kubeletCli) = obj {
	kubeletCliData = kubeletCli.data
	not contains(kubeletCliData["fullCommand"], "client-ca-file")
	obj = kubeletCli
}