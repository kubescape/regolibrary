package armo_builtins
import data.cautils as cautils


deny[msg] {
		kubelet_info := input[_]
		kubelet_info.kind == "KubeletInfo"
		kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
        kubelet_client_ca_file := kubelet_info.data.clientCAFile
        kubelet_client_ca_file
        cautils.is_not_strict_conf_permission(kubelet_client_ca_file.permissions)
		msg := {
			"alertMessage": "kubelet configuration file permissions are too permissive",
			"alertScore": 2,
       		"failedPaths": [],
       		"fixPaths":[],
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [kubelet_info]
			},
		}
	}
