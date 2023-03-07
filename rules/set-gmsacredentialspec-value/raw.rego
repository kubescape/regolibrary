package armo_builtins

import future.keywords.if

# Rule to check if the GMSA credential spec is set in the security context
deny[msga] {
    # Verify the object kind
    obj := input[_]
    allowed_kinds := {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}
    allowed_kinds[obj.kind]

    # Check if the GMSA credential spec is set in the security context
    not gmsaCredentialSpecSet(getSecurityContext(obj))

    path := sprintf("%v.securityContext.gmsaCredentialSpec", [obj.kind])
    msga := {
        "alertMessage": sprintf("%v: %v does not set 'securityContext.gmsaCredentialSpec' with allowed value", [obj.kind, obj.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [path],
        "fixPaths": [],
        "alertObject": {
            "k8sApiObjects": [obj]
        }
    }
}

# Function to check if the GMSA credential spec is set in the security context
gmsaCredentialSpecSet(securityContext) := true if {
    securityContext != null
    securityContext.windowsOptions != null
    securityContext.windowsOptions.gmsaCredentialSpec != null
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
