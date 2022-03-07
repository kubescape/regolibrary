package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"
		kubeletCliData := kubeletCli.data

		isTlsDisabledBoth(kubeletConfig, kubeletCliData)


		msga := {
			"alertMessage": "kubelet client TLS authentication is not enabled",
			"alertScore": 2,
			"fixPaths": [],
			"failedPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [kubeletConfig, kubeletCli]
			},
		}
	}


deny[msga] {
		externalObj := isTlsDisabledSingle(input)


		msga := {
			"alertMessage": "kubelet client TLS authentication is not enabled",
			"alertScore": 2,
			"fixPaths": [],
			"failedPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [externalObj]
			},
		}
	}



# CLI overrides config
isTlsDisabledBoth(kubeletConfig, kubeletCli) {
    isNotTlsCli(kubeletCli)
    isNotTlsConfig(kubeletConfig)
}

isTlsDisabledSingle(resources) = obj {
	kubeletCli := resources[_]            
	kubeletCli.kind == "KubeletCommandLine"
	kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletConfig := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubeletConfig) == 0

	isNotTlsCli(kubeletCli)

	obj = kubeletCli
}


isTlsDisabledSingle(resources) = obj {
	kubeletConfig := resources[_]
	kubeletConfig.kind == "KubeletConfiguration"
	kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletCli := [cli | cli = resources[_]; cli.kind == "KubeletCommandLine"]
	count(kubeletCli) == 0

	isNotTlsConfig(kubeletConfig)

	obj = kubeletConfig
}


isNotTlsCli(kubeletCli) {
	kubeletCliData := kubeletCli.data
	not contains(kubeletCliData["fullCommand"], "tls-cert-file")
	not contains(kubeletCliData["fullCommand"], "tls-private-key-file")
}

isNotTlsConfig(kubeletConfig){
    not kubeletConfig.data.tlsCertFile
    not kubeletConfig.data.tlsPrivateKeyFile
}
