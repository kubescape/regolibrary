# Regostore
Here we store regos

### [MITRE Framework](https://www.microsoft.com/security/blog/wp-content/uploads/2021/03/Matrix-1536x926.png)

| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access| Discovery | Lateral Movement | Collection | Impact |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | 
|Using Cloud credentials|[Exec into container](/controls/execintocontainer.json)|[Backdoor container](/controls/backdoorcontainer.json)|[Privileged container](/controls/privilegedcontainer.json)|[Clear container logs](/controls/clearcontainerlogs.json)|[List k8s secrets](/controls/ListKubernetessecrets.json)|[Access the K8S API server](/controls/accessthek8sAPIserver.json)|Access cloud resources|[Image from private registery](/controls/imagefromPrivateRegistry.json)|[Data Destruction](/controls/datadestruction.json) ||
|[Compromised Image in registery](/controls/compromisedimagesinregistry.json)| [bash/cmd inside container](/controls/bash-cmdinsidecontainer.json)|[Writable hostPath mount](/controls/writablehostPathmount.json)|[Cluster-admin binding](/controls/cluster-adminbinding.json)|[Delete K8S events](/controls/deleteKubernetesevents.json)|[Mount service principal](/controls/mountserviceprincipal.json)|[Access Kubelet API](/controls/accesskubeletAPI.json)|[Container service account](/controls/accesscontainerserviceaccount.json)||[Resources Hijacking](/controls/resourcehijacking.json)||
|kubeconfig file|[New container](/controls/newcontainer.json)|[kubernetes CronJob](/controls/kubernetescronJob.json)|[hostPath mount](/controls/hostPathmount.json)|[Pod/Container name similarity](/controls/namesimilarity.json)|[Access container service account](/controls/accesscontainerserviceaccount.json)|[Network mapping](/controls/networkmapping.json)|[Cluster internal networking](/controls/clusterInternalnetworking.json)||Denial of service||
|[Application vulnerability](/controls/vulnerableapplication.json)|[Application Exploit (RCE)](/controls/applicationexploitRCE.json)|[Malicious admission controller](/controls/maliciousadmissioncontroller-mutating.json)|Access cloud resources| Connect from Proxy server| [Application credentials in configuration files](/controls/Applicationscredentialsinconfigurationfiles.json)|[Access kubernetes dashboard](/controls/accessk8sdashboard.json)|[Application credentials in configuration](/controls/Applicationscredentialsinconfigurationfiles.json)|||||
|[Exposed Dashboard](/controls/exposeddashboard.json)|[SSH server running insider container](/controls/SSHserverrunninginsidecontainer.json)||||Access managed identity credentials|[instance Metadata API](/controls/instancemetadataAPI..json)|[Writable volume mounts on the host](/controls/writablehostPathmount.json)||||
|[Exposed sensitive interface](/controls/exposedsensitiveinterfaces.json)|[Sidecar injection](/controls/sidecarinjection.json)||||[Malicious admission controller](/controls/maliciousadmissioncontroller-validating.json)||[Access kubernetes dashboard](/controls/accessk8sdashboard.json)||||
||||||||[access tiller endpoint](/controls/accesstillerendpoint.json)|||||
||||||||[CoreDNS poisoning](/controls/coreDNSpoisoning.json)|||||
||||||||ARP and IP spoofing|||||

### [NSA Framework](https://www.nsa.gov/News-Features/Feature-Stories/Article-View/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)
