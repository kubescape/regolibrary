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

		isTlsDisabled(kubeletConfig, kubeletCliData)


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

isNotTlsCli(kubeletCliData) {
	not contains(kubeletCliData["fullCommand"], "tls-cert-file")
	not contains(kubeletCliData["fullCommand"], "tls-private-key-file")
}

isNotTlsConfig(kubeletConfig){
    not kubeletConfig.data.tlsCertFile
    not kubeletConfig.data.tlsPrivateKeyFile
}