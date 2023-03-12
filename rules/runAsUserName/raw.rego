package armo_builtins

import future.keywords.if
import data.kubernetes

deny[msg] {
    # Verify the object kind
    obj := input[_]
    allowed_kinds := {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}
    allowed_kinds[obj.kind]

    # Check if the node's operating system is Windows
    node := getNode(obj)
    node.metadata.labels["kubernetes.io/os"] == "windows"

    # Check if the runAsUserName field is set in the security context
    not runAsUserNameSet(getSecurityContext(obj))

    path := sprintf("%v.securityContext.runAsUserName", [obj.kind])
    msg := {
        "alertMessage": sprintf("%v: %v does not set 'securityContext.runAsUserName' with allowed value", [obj.kind, obj.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [path],
        "fixPaths": [],
        "alertObject": {
            "k8sApiObjects": [obj]
        }
    }
}

# Function to check if the runAsUserName field is set in the security context
runAsUserNameSet(securityContext) := true {
    securityContext.windowsOptions.runAsUserName != null
} else := false

# Function to get the security context of an object
getSecurityContext(obj) = obj.spec.securityContext {
    obj.kind == "Pod"
} else = obj.spec.template.spec.securityContext {
    any([obj.kind == "Deployment",
     obj.kind == "ReplicaSet",
     obj.kind == "DaemonSet",
     obj.kind == "StatefulSet",obj.kind == "Job"])
} else = obj.spec.jobTemplate.spec.template.spec.securityContext {
    obj.kind == "CronJob"
} else = null

# Function to get the node object of a pod
getNode(obj) = node {
    obj.kind == "Pod"
    node := data.kubernetes.nodes[obj.spec.nodeName]
} else = node {
    any([obj.kind == "Deployment",
     obj.kind == "ReplicaSet",
     obj.kind == "DaemonSet",
     obj.kind == "StatefulSet",obj.kind == "Job"])
    pods := data.kubernetes.pods
    pod_names := [pod.metadata.name | pod := pods[_] | pod.spec.nodeName == obj.spec.nodeName]
    node := data.kubernetes.nodes[obj.spec.nodeName] {count(pod_names) > 0}
} else = node {
    obj.kind == "CronJob"
    jobs := data.kubernetes.jobs
    job_names := [job.metadata.name | job := jobs[_] | job.spec.nodeName == obj.spec.nodeName]
    pod_names := [p.metadata.name | job := jobs[_] | job.spec.nodeName == obj.spec.nodeName | p := data.kubernetes.pods[_] | p.metadata.labels["job-name"] == job.metadata.name]
    node := data.kubernetes.nodes[obj.spec.nodeName] {count(job_names) > 0 and count(pod_names) > 0}
} else = null
