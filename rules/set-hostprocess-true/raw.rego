package armo_builtins

import future.keywords.if

# Rule to check if container is set as a 'Host Process' container
deny[msg] {
    # Verify the object kind
    obj := input[_]
    allowed_kinds := {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}
    allowed_kinds[obj.kind]

    # Check if HostProcess is set to true
    not isHostProcessSet(obj)

    path := sprintf("%v.spec.hostProcess", [obj.kind])
    msg := {
        "alertMessage": sprintf("%v: %v does not set 'spec.hostProcess' with allowed value", [obj.kind, obj.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [path],
        "fixPaths": [],
        "alertObject": {
            "k8sApiObjects": [obj]
        }
    }
}

# Function to check if container is set as a 'Host Process' container
isHostProcessSet(obj) := true if {
    obj.spec.hostProcess == true
    # Check if WindowsHostProcessContainers feature flag is enabled
    windowsHostProcessEnabled(obj.data.APIServerInfo.cmdLine)
} else := false

# Function to check if the WindowsHostProcessContainers feature flag is enabled in the API server
windowsHostProcessEnabled(command) {
	contains(command, "--feature-gates=")
	args := regex.split(" +", command)
	some i
	regex.match("WindowsHostProcessContainers=true", args[i])
}