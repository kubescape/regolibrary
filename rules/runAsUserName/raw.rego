package armo_builtins

import future.keywords.if
import data.kubernetes

# Fails if pod does not define runAsUserName
deny[msg] {
    wl := input[_]
    wl.kind == "Pod"
    spec := wl.spec
    path_to_search := ["PodSecurityContext", "SecurityContext"]

    no_runAsUser_in_securityContext(spec, path_to_search)

    path_to_containers := ["spec", "containers"]
    containers := object.get(wl, path_to_containers, [])
    container := containers[i]
    no_runAsUser_in_securityContext(container, path_to_search)

    fix_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)]) 
    fixPaths := [{"path": fix_path, "value": "YOUR_VALUE"}]
    
    # Check if the node's operating system is Windows
  	system_info := input[_]
	system_info.kind == "Node"
	system_info.metadata.labels.kubernetes.io/os == "windows"


    path := sprintf("%v.securityContext.runAsUserName", [wl.kind])
    msg := {
        "alertMessage": sprintf("Pod: %v does not set 'securityContext.runAsUserName' with allowed value", [wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [path],
        "fixPaths": fixPaths,
        "alertObject": {
            "k8sApiObjects": [wl]
        }
    }
}

# Fails if workload does not define runAsUserName
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    spec := wl.spec.template.spec
	path_to_search := ["PodSecurityContext", "securityContext"]
	no_runAsUser_in_securityContext(spec, path_to_search)

	path_to_containers := ["spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
    no_runAsUser_in_securityContext(container, path_to_search)

	fix_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)]) 
	fixPaths := [{"path": fix_path, "value": "YOUR_VALUE"}]
	system_info := input[_]
	system_info.kind == "Node"
	system_info.metadata.labels.kubernetes.io/os == "windows"

	msga := {
		"alertMessage": sprintf("Workload: %v does not set 'securityContext.runAsUserName' with allowed value", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if CronJob does not define seLinuxOptions 
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	spec := wl.spec.jobTemplate.spec.template.spec
	path_to_search := ["PodSecurityContext", "securityContext"]
	no_runAsUser_in_securityContext(spec, path_to_search)

	path_to_containers := ["spec", "jobTemplate", "spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
    no_runAsUser_in_securityContext(container, path_to_search)

	system_info := input[_]
	system_info.kind == "Node"
	system_info.metadata.labels.kubernetes.io/os == "windows"

	fix_path := sprintf("%s[%d].%s", [concat(".", path_to_containers), i, concat(".", path_to_search)]) 
	fixPaths := [{"path": fix_path, "value": "YOUR_VALUE"}]
	msga := {
		"alertMessage": sprintf("Cronjob: %v does not set 'securityContext.runAsUserName' with allowed value", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

no_runAsUser_in_securityContext(spec, path_to_search){
    object.get(spec, path_to_search, "") == ""
}
# Function to get the node object of a pod
getNode(obj) = node {
    obj.kind == "Pod"
    node := data.kubernetes.nodes[obj.spec.nodeName]
} 