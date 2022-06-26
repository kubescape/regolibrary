package armo_builtins
import data.cautils as cautils


deny[msg] {
		kubeproxy_info := input[_]
		kubeproxy_info.kind == "KubeProxyInfo"
		kubeproxy_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
        kubeproxy_kubeconfig := kubeproxy_info.data.kubeConfigFile
        kubeproxy_kubeconfig
        cautils.is_not_strict_conf_permission(kubeproxy_kubeconfig.permissions)
		msg := {
			"alertMessage": "kubeproxy kubeconfig file permissions are too permissive",
			"alertScore": 2,
       		"failedPaths": [],
       		"fixPaths":[],
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [kubeproxy_info]
			},
		}
	}
