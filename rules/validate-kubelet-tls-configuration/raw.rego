package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.armo.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.armo.cloud/v1beta0"

		isTlsDisabled(kubeletConfig, kubeletCli)


		msga := {
			"alertMessage": "kubelet client TLS authentication is not enabled",
			"alertScore": 2,
			"failedPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [kubeletConfig, kubeletCli]
			},
		}
	}

# CLI overrides config
isTlsDisabled(kubeletConfig, kubeletCli) {
    isNotTlsCli(kubeletCli)
    isNotTlsConfig(kubeletConfig)
}

isNotTlsCli(kubeletCli) {
    not kubeletCli.data["tls-cert-file"]
    not kubeletCli.data["tls-private-key-file"]
}

isNotTlsConfig(kubeletConfig){
    not kubeletConfig.data.tlsCertFile
    not kubeletConfig.data.tlsPrivateKeyFile
}