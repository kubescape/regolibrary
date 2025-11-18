package armo_builtins

# Deny Azure Application Gateway Ingress resources without TLS configured
deny[msga] {
  ingress := input[_]
  ingress.kind == "Ingress"

  # Filter for Azure Application Gateway Ingress
  isAzureIngress(ingress)

  # Check if TLS is not configured
  not isTLSSet(ingress.spec)

  # Prepare message data
  alert_message := sprintf("Ingress '%v' has no TLS configured", [ingress.metadata.name])
  failed_paths := ["spec.tls"]
  fixed_paths := [{"path": "spec.tls", "value": "YOUR_TLS_CONFIG"}]

  msga := {
    "alertMessage": alert_message,
    "packagename": "armo_builtins",
    "alertScore": 7,
    "reviewPaths": ["spec.tls"],
    "failedPaths": failed_paths,
    "fixPaths": fixed_paths,
    "alertObject": {
      "k8sApiObjects": [ingress]
    }
  }
}

# Check if TLS is configured on the Ingress
isTLSSet(spec) {
  count(spec.tls) > 0
}

# Check if this is an Azure Application Gateway Ingress
isAzureIngress(ingress) {
  ingress.metadata.annotations["kubernetes.io/ingress.class"] == "azure/application-gateway"
}

isAzureIngress(ingress) {
  ingress.spec.ingressClassName == "azure-application-gateway"
}
