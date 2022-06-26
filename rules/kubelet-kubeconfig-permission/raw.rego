package armo_builtins
import data.cautils as cautils


deny[msg] {
		kubelet_info := input[_]
		kubelet_info.kind == "KubeletInfo"
		kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
        kubelet_kubeconfig := kubelet_info.data.kubeConfigFile
        kubelet_kubeconfig
        cautils.is_not_strict_conf_permission(kubelet_kubeconfig.permissions)
		msg := {
			"alertMessage": "kubelet kubeconfig file permissions are too permissive",
			"alertScore": 2,
       		"failedPaths": [],
       		"fixPaths":[],
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [kubelet_info]
			},
		}
	}
