package armo_builtins
import data.cautils as cautils
    
# ========= RCE : no service score 5 ================
deny[msga] {
	pod := input[_]
	container := pod.spec.containers[i]
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]
    is_unsafe_image(scan)
	scan.containersScanID
	vulnerabilities := armo.get_image_scan_details({"containersScanID":scan.containersScanID, "fieldCreteria":{"description":"RCE|like,Remote Code Execution|like,remote code execution|like,remote command execution|like,Remote Command Execution|like,arbitrary code|like,code execution|like,Arbitrary Code|like,Code Execution|like,code injection|like,Code Injection|like,execute code|like,Execute Code|like,arbitrary command|like,Arbitrary Command|like,arbitrary commands|like,Arbitrary Commands|like,command injection|like,Command Injection|like,command execution|like,Command Execution|like,inject arbitrary commands|like,Inject Arbitrary Commands|like"} })
	count(vulnerabilities) > 0
	t := { "containersScanID": scan.containersScanID,"count":count(vulnerabilities),"vulnerabilities":vulnerabilities}

    msga := {
        "alertMessage": sprintf("image %v has %v RCE vulnerabilities", [container.image,count(vulnerabilities)]),
        "alertScore": 5,
		"failedPaths": [path],
        "packagename": "armo_builtins",
        "alertObject": {
			"k8sApiObjects": [pod],
			"externalObjects": {
				"vulnerabilities" : [vulnerabilities]
			}
		},
    }
}

# workloads
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]

    is_unsafe_image(scan)
	scan.containersScanID
	vulnerabilities := armo.get_image_scan_details({"containersScanID":scan.containersScanID, "fieldCreteria":{"description":"RCE|like,Remote Code Execution|like,remote code execution|like,remote command execution|like,Remote Command Execution|like,arbitrary code|like,code execution|like,Arbitrary Code|like,Code Execution|like,code injection|like,Code Injection|like,execute code|like,Execute Code|like,arbitrary command|like,Arbitrary Command|like,arbitrary commands|like,Arbitrary Commands|like,command injection|like,Command Injection|like,command execution|like,Command Execution|like,inject arbitrary commands|like,Inject Arbitrary Commands|like"} })
	count(vulnerabilities) > 0
	t := { "containersScanID": scan.containersScanID,"count":count(vulnerabilities),"vulnerabilities":vulnerabilities}

    msga := {
        "alertMessage": sprintf("image %v has %v RCE vulnerabilities", [container.image,count(vulnerabilities)]),
        "alertScore": 5,
		"failedPaths": [path],
        "packagename": "armo_builtins",
        "alertObject": {
			"k8sApiObjects": [wl],
			"externalObjects": {
				"vulnerabilities" : [vulnerabilities]
			}
		},
    }
}

# cronjobs
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v]", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]

    is_unsafe_image(scan)
	scan.containersScanID
	vulnerabilities := armo.get_image_scan_details({"containersScanID":scan.containersScanID, "fieldCreteria":{"description":"RCE|like,Remote Code Execution|like,remote code execution|like,remote command execution|like,Remote Command Execution|like,arbitrary code|like,code execution|like,Arbitrary Code|like,Code Execution|like,code injection|like,Code Injection|like,execute code|like,Execute Code|like,arbitrary command|like,Arbitrary Command|like,arbitrary commands|like,Arbitrary Commands|like,command injection|like,Command Injection|like,command execution|like,Command Execution|like,inject arbitrary commands|like,Inject Arbitrary Commands|like"} })
	count(vulnerabilities) > 0
	t := { "containersScanID": scan.containersScanID,"count":count(vulnerabilities),"vulnerabilities":vulnerabilities}

    msga := {
        "alertMessage": sprintf("image %v has %v RCE vulnerabilities", [container.image,count(vulnerabilities)]),
        "alertScore": 5,
		"failedPaths": [path],
        "packagename": "armo_builtins",
        "alertObject": {
			"k8sApiObjects": [wl],
			"externalObjects": {
				"vulnerabilities" : [vulnerabilities]
			}
		},
    }
}

# ======== RCE + service (not nodeport and not loadbalancer) 7 =====================
deny[msga] {
	pod := input[_]
	container := pod.spec.containers[i]
	path := sprintf("spec.containers[%v]", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]

    is_unsafe_image(scan)
	scan.containersScanID
	vulnerabilities := armo.get_image_scan_details({"containersScanID":scan.containersScanID, "fieldCreteria":{"description":"RCE|like,Remote Code Execution|like,remote code execution|like,remote command execution|like,Remote Command Execution|like,arbitrary code|like,code execution|like,Arbitrary Code|like,Code Execution|like,code injection|like,Code Injection|like,execute code|like,Execute Code|like,arbitrary command|like,Arbitrary Command|like,arbitrary commands|like,Arbitrary Commands|like,command injection|like,Command Injection|like,command execution|like,Command Execution|like,inject arbitrary commands|like,Inject Arbitrary Commands|like"} })
	count(vulnerabilities) > 0
	t := { "containersScanID": scan.containersScanID,"count":count(vulnerabilities),"vulnerabilities":vulnerabilities}

	service := input[_]
	service.kind == "Service"
	service.metadata.namespace == pod.metadata.namespace
	labels := pod.metadata.labels
	filtered_labels := json.remove(labels, ["pod-template-hash"])
	np_or_lb := {"NodePort", "LoadBalancer"}
	not np_or_lb[service.spec.type]
	cautils.is_subobject(service.spec.selector, filtered_labels)

    msga := {
        "alertMessage": sprintf("image %v has %v RCE vulnerabilities", [container.image,count(vulnerabilities)]),
        "alertScore": 7,
		"failedPaths": [path],
        "packagename": "armo_builtins",
        "alertObject": {
			"k8sApiObjects": [pod],
			"externalObjects": {
				"vulnerabilities" : [vulnerabilities]
			}
		},
    }
}

# workloads
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	path := sprintf("spec.template.spec.containers[%v]", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]

    is_unsafe_image(scan)
	scan.containersScanID
	vulnerabilities := armo.get_image_scan_details({"containersScanID":scan.containersScanID, "fieldCreteria":{"description":"RCE|like,Remote Code Execution|like,remote code execution|like,remote command execution|like,Remote Command Execution|like,arbitrary code|like,code execution|like,Arbitrary Code|like,Code Execution|like,code injection|like,Code Injection|like,execute code|like,Execute Code|like,arbitrary command|like,Arbitrary Command|like,arbitrary commands|like,Arbitrary Commands|like,command injection|like,Command Injection|like,command execution|like,Command Execution|like,inject arbitrary commands|like,Inject Arbitrary Commands|like"} })
	count(vulnerabilities) > 0
	t := { "containersScanID": scan.containersScanID,"count":count(vulnerabilities),"vulnerabilities":vulnerabilities}

	service := input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	labels := wl.spec.template.metadata.labels
	np_or_lb := {"NodePort", "LoadBalancer"}
	not np_or_lb[service.spec.type]
	cautils.is_subobject(service.spec.selector,labels)

    msga := {
        "alertMessage": sprintf("image %v has %v RCE vulnerabilities", [container.image,count(vulnerabilities)]),
        "alertScore": 7,
		"failedPaths": [path],
        "packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl],
			"externalObjects": {
				"vulnerabilities" : [vulnerabilities]
			}
		},
    
    }
}
# cronjobs
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v]", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]

    is_unsafe_image(scan)
	scan.containersScanID
	vulnerabilities := armo.get_image_scan_details({"containersScanID":scan.containersScanID, "fieldCreteria":{"description":"RCE|like,Remote Code Execution|like,remote code execution|like,remote command execution|like,Remote Command Execution|like,arbitrary code|like,code execution|like,Arbitrary Code|like,Code Execution|like,code injection|like,Code Injection|like,execute code|like,Execute Code|like,arbitrary command|like,Arbitrary Command|like,arbitrary commands|like,Arbitrary Commands|like,command injection|like,Command Injection|like,command execution|like,Command Execution|like,inject arbitrary commands|like,Inject Arbitrary Commands|like"} })
	count(vulnerabilities) > 0
	t := { "containersScanID": scan.containersScanID,"count":count(vulnerabilities),"vulnerabilities":vulnerabilities}

	service := input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	labels := wl.spec.jobTemplate.spec.template.metadata.labels
	np_or_lb := {"NodePort", "LoadBalancer"}
	not np_or_lb[service.spec.type]
	cautils.is_subobject(service.spec.selector,labels)

    msga := {
        "alertMessage": sprintf("image %v has %v RCE vulnerabilities", [container.image,count(vulnerabilities)]),
        "alertScore": 7,
		"failedPaths": [path],
        "packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl],
			"externalObjects": {
				"vulnerabilities" : [vulnerabilities]
			}
		},
    }
}

# ======= RCE + service nodeport/loadbalancer 10 ===========================
deny[msga] {
	pod := input[_]
	container := pod.spec.containers[i]
	path := sprintf("spec.containers[%v]", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]

    is_unsafe_image(scan)
	scan.containersScanID
	vulnerabilities := armo.get_image_scan_details({"containersScanID":scan.containersScanID, "fieldCreteria":{"description":"RCE|like,Remote Code Execution|like,remote code execution|like,remote command execution|like,Remote Command Execution|like,arbitrary code|like,code execution|like,Arbitrary Code|like,Code Execution|like,code injection|like,Code Injection|like,execute code|like,Execute Code|like,arbitrary command|like,Arbitrary Command|like,arbitrary commands|like,Arbitrary Commands|like,command injection|like,Command Injection|like,command execution|like,Command Execution|like,inject arbitrary commands|like,Inject Arbitrary Commands|like"} })
	count(vulnerabilities) > 0
	t := { "containersScanID": scan.containersScanID,"count":count(vulnerabilities),"vulnerabilities":vulnerabilities}

	service := input[_]
	service.kind == "Service"
	service.metadata.namespace == pod.metadata.namespace
	labels := pod.metadata.labels
	filtered_labels := json.remove(labels, ["pod-template-hash"])
	np_or_lb := {"NodePort", "LoadBalancer"}
	np_or_lb[service.spec.type]
	cautils.is_subobject(service.spec.selector, filtered_labels)

    msga := {
        "alertMessage": sprintf("image %v has %v RCE vulnerabilities", [container.image,count(vulnerabilities)]),
        "alertScore": 10,
		"failedPaths": [path],
        "packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [pod],
			"externalObjects": {
				"vulnerabilities" : [vulnerabilities]
			}
		},
    }
}

# workloads
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	path := sprintf("spec.template.spec.containers[%v]", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]

    is_unsafe_image(scan)
	scan.containersScanID
	vulnerabilities := armo.get_image_scan_details({"containersScanID":scan.containersScanID, "fieldCreteria":{"description":"RCE|like,Remote Code Execution|like,remote code execution|like,remote command execution|like,Remote Command Execution|like,arbitrary code|like,code execution|like,Arbitrary Code|like,Code Execution|like,code injection|like,Code Injection|like,execute code|like,Execute Code|like,arbitrary command|like,Arbitrary Command|like,arbitrary commands|like,Arbitrary Commands|like,command injection|like,Command Injection|like,command execution|like,Command Execution|like,inject arbitrary commands|like,Inject Arbitrary Commands|like"} })
	count(vulnerabilities) > 0
	t := { "containersScanID": scan.containersScanID,"count":count(vulnerabilities),"vulnerabilities":vulnerabilities}

	service := input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	labels := wl.spec.template.metadata.labels
	np_or_lb := {"NodePort", "LoadBalancer"}
	np_or_lb[service.spec.type]
	cautils.is_subobject(service.spec.selector,labels)

    msga := {
        "alertMessage": sprintf("image %v has %v RCE vulnerabilities", [container.image,count(vulnerabilities)]),
        "alertScore": 10,
		"failedPaths": [path],
        "packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl],
			"externalObjects": {
				"vulnerabilities" : [vulnerabilities]
			}
		},
    }
}

# cronjobs
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v]", [format_int(i, 10)])
    res := armo.get_image_scan_summary({"type":"imageTag","value":container.image,"size":1})
	scan := res[_]

    is_unsafe_image(scan)
	scan.containersScanID
	vulnerabilities := armo.get_image_scan_details({"containersScanID":scan.containersScanID, "fieldCreteria":{"description":"RCE|like,Remote Code Execution|like,remote code execution|like,remote command execution|like,Remote Command Execution|like,arbitrary code|like,code execution|like,Arbitrary Code|like,Code Execution|like,code injection|like,Code Injection|like,execute code|like,Execute Code|like,arbitrary command|like,Arbitrary Command|like,arbitrary commands|like,Arbitrary Commands|like,command injection|like,Command Injection|like,command execution|like,Command Execution|like,inject arbitrary commands|like,Inject Arbitrary Commands|like"} })
	count(vulnerabilities) > 0
	t := { "containersScanID": scan.containersScanID,"count":count(vulnerabilities),"vulnerabilities":vulnerabilities}

	service := input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	labels := wl.spec.jobTemplate.spec.template.metadata.labels
	np_or_lb := {"NodePort", "LoadBalancer"}
	np_or_lb[service.spec.type]
	cautils.is_subobject(service.spec.selector,labels)

    msga := {
        "alertMessage": sprintf("image %v has %v RCE vulnerabilities", [container.image,count(vulnerabilities)]),
        "alertScore": 10,
		"failedPaths": [path],
        "packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl],
			"externalObjects": {
				"vulnerabilities" : [vulnerabilities]
			}
		},
    }
}

#treat as potentially critical
is_unsafe_image(scanresult) {
	scanresult.numOfUnknownSeverity > 0
}
is_unsafe_image(scanresult) {
	scanresult.numOfNegligibleSeverity > 0
}

is_unsafe_image(scanresult) {
	scanresult.numOfLowSeverity > 0
}

is_unsafe_image(scanresult) {
	scanresult.numOfMeduiumSeverity > 0
}

is_unsafe_image(scanresult) {
	scanresult.numOfHighSeverity > 0
}

is_unsafe_image(scanresult) {
	scanresult.numOfCriticalSeverity > 0
}