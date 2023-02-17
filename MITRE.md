# ARMO rego library

[Kubescape](https://github.com/kubescape/kubescape) rego library for detecting miss-configurations in Kubernetes manifests

### [NSA Framework](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)

### [MITRE ATT&CK® Framework](https://www.microsoft.com/security/blog/wp-content/uploads/2021/03/Matrix-1536x926.png)

| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access| Discovery | Lateral Movement | Collection | Impact |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | 
|Using Cloud credentials|Exec into container|Backdoor container|Privileged container|Clear container logs|List k8s secrets|Access the K8S API server|Access cloud resources|Image from private registry|Data Destruction||
|Compromised Image in registry| bash/cmd inside container|Writable hostPath mount|Cluster-admin binding|Delete K8S events|Mount service principal|Access Kubelet API|Container service account||Resources Hijacking||
|kubeconfig file|New container|kubernetes CronJob|hostPath mount|Pod/Container name similarity|Access container service account|Network mapping|Cluster internal networking||Denial of service||
|Application vulnerability|Application Exploit (RCE)|Malicious admission controller|Access cloud resources| Connect from Proxy server|Application credentials in configuration files|Access kubernetes dashboard|Application credentials in configuration|||||
|Exposed Dashboard|SSH server running insider container||||Access managed identity credentials|instance Metadata API|Writable volume mounts on the host||||
|Exposed sensitive interface|Sidecar injection||||Malicious admission controller||Access kubernetes dashboard||||
||||||||access tiller endpoint|||||
||||||||CoreDNS poisoning|||||
||||||||ARP and IP spoofing|||||


## Testing
See [testing](testrunner/README.md)
