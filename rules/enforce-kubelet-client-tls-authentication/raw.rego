package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.armo.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.armo.cloud/v1beta0"

		isClientTlsDisabled(kubeletConfig, kubeletCli)


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
isClientTlsDisabled(kubeletConfig, kubeletCli) {
	not kubeletCli.data["client-ca-file"]
    not kubeletConfig.data.authentication.x509.clientCAFile
}
