<!-- markdown-link-check-disable -->
[![Version](https://img.shields.io/github/v/release/kubescape/regolibrary)](releases)
[![release-date](https://img.shields.io/github/release-date/kubescape/regolibrary)](releases)
<!-- markdown-link-check-enable-->
[![GitHub](https://img.shields.io/github/license/kubescape/kubescape)](https://github.com/kubescape/kubescape/blob/master/LICENSE)
<!-- markdown-link-check-enable-->

# Kubescape Regolibrary

This repository contains a library of security controls that codify Kubernetes best practices derived from the most prevalent security frameworks in the industry. [Kubescape](https://github.com/kubescape/kubescape) uses these controls to scan again running clusters or manifest files under development. They’re written in Rego, the purpose-built declarative policy language that supports Open Policy Agent (OPA).


## Terminology

- **Framework** - a group of controls to test against

- **Control** - a potential vulnerability to check, can include multiple rules

- **Rule** - a single specific test

## Contributing

### Add a framework

Add `frameworkName.json` file in the `/frameworks` directory

Example of a framework:
```json
{
    "name": "DevOpsBest",
    "description": "This framework is recommended for use by devops.",
    "attributes": {
      "armoBuiltin": true
    },
    "scanningScope": {
        "matches": [
            "cluster",
            "file"
        ]
    },
    "controlsNames": [
        "Naked pods",
        "Container runtime socket mounted",
        "Image pull policy on latest tag",
        "Label usage for resources",
        "K8s common labels usage",
        "Pods in default namespace",
        "Container hostPort",
        "Resources CPU limit and request",
        "Resources memory limit and request",
        "Configured liveness probe",
        "Configured readiness probe"
    ]
}
```
* Attribute `"armoBuiltin": true` - mandatory for armo rules. Only ARMO team members are authorized to create builtin objects.
* controlNames - List of controls to run, must be exact name. Use copy-paste to be sure.
* `scanningScope` - this framework will run just if kubescape scan process match to the scope in the list.(for example the framework above will run if the running kubescape scan is for scanning cluster or file) - list of allowed scanning scope ``` [["cluster", "file"], ["cluster"], ["cloud"], ["GKE"], ["EKS"], ["AKS"]] ```. `cloud` meaning - will run just on managed cluster


### Add a control

Add `controlName.json` file in the `/controls` directory.

Example of a control:
```json
{
    "name": "Pods in default namespace",
    "attributes": {
        "armoBuiltin": true
    },
    "description": "It is recommended to avoid running pods in cluster without explicit namespace assignment. This control identifies all the pods running in the default namespace.",
    "remediation": "Create necessary namespaces and move all the pods from default namespace there.",
    "rulesNames": [
        "pods-in-default-namespace"
    ],
    "long_description": "It is recommended to avoid running pods in cluster without explicit namespace assignment. This may lead to wrong capabilities and permissions assignment and potential compromises. This control identifies all the pods running in the default namespace.",
    "test": "Check that there are no pods in the 'default' namespace",
    "id": "C-0061",
    "controlID": "C-0061",
    "baseScore": 3, 
    "scanningScope": {
        "matches": [
            "cluster",
            "file"
        ]
    },
     "category": {
        "name" : "Workload",
        "subCategory": {
            "name": "Resource management"
        }
   }
}
```
* Attribute `"armoBuiltin": true` - mandatory for armo rules. Only ARMO team members are authorized to create builtin objects.
* `rulesNames` -  List of rules to run, must be exact name. Use copy-paste to be sure.
* `scanningScope` - this control will run just if kubescape scan process match to the scope in the list.(for example the control above will run if the running kubescape scan is for scanning cluster or file) - list of allowed scanning scope ``` [["cluster", "file"], ["cluster"], ["cloud"], ["GKE"], ["EKS"], ["AKS"]] ```. `cloud` meaning - will run just on managed cluster
* `category` - The category the control belongs to. Some controls may also define a `subCategory`. The available categories/sub categories are listed under the `mapCategoryNameToID.json` file, mapped to their respective IDs
* `subCategory` - A sub category for a `category` (optional). Must be listed under the  `mapCategoryNameToID.json` file


* `long_description`, `test` and other control fields are used mainly in the [documentation](https://hub.armosec.io/docs)

* See [control go struct](https://github.com/kubescape/opa-utils/blob/master/reporthandling/datastructures.go#L56) for more control fields

### Add a rule:

1. Add to `/rules` a new directory with the rule name

2. Add to the rule directory file - `rule.metadata.json`:

Example of rule.metadata.json:
```json
{
    "name": "resources-cpu-limit-and-request",
    "attributes": {
      "armoBuiltin": true
    },
    "ruleLanguage": "Rego",
    "match": [
      {
        "apiGroups": [
          ""
        ],
        "apiVersions": [
          "v1"
        ],
        "resources": [
          "Pod"
        ]
      }
    ],
    "ruleDependencies": [
    ],
    "controlConfigInputs": [
      {
        "path": "settings.postureControlInputs.cpu_request_max",
        "name": "cpu_request_max",
        "description": "Ensure CPU max requests are set"
      }
    ],
    "description": "CPU limits and requests are not set.",
    "remediation": "Ensure CPU limits and requests are set.",
    "ruleQuery": "armo_builtins"
}
```
* Attribute `"armoBuiltin": true` - mandatory for armo rules. Only ARMO team members are authorized to create builtin objects.


* See [rule go struct](https://github.com/kubescape/opa-utils/blob/master/reporthandling/datastructures.go#L37) for further explanations of rule fields
* Optional attributes :
  * `"hostSensorRule": "true"` - indicates the rule gets information from the host scanner

  * `"useFromKubescapeVersion"` - add if rule is only supported from a certain Kubescape version. Inclusive.

  * `"useUntilKubescapeVersion"` - add if a newer version exists so the control doesn’t run both. Inclusive. 

  * `"imageScanRelated": true` - indicates that rule uses information from image scanning.

  * `"controlConfigInputs"` - A list the rule uses and can be configured by the user. See example above.


3. Add to the new rule directory a new file - `raw.rego`

    This is where the logic of the rule is. 
    Example of `raw.rego`:
    ```rego
    package armo_builtins

    deny[msga] {

        pod := input[_]
        pod.kind == "Pod"
        container := pod.spec.containers[i]
        container.securityContext.privileged == true
        path := sprintf("containers[%d].securityContext.privileged", [i])

        msga := {
            "alertMessage": sprintf("pod: %v is defined as privileged", [pod.metadata.name]),
            "packagename": "armo_builtins",
            "fixPaths": [],
            "failedPaths": path,
            "alertObject": {
                "k8sApiObjects": [pod]
            }
        }
    }
    ```
    Use [opa rego reference](https://www.openpolicyagent.org/docs/latest/policy-reference/) for help with syntax

    See structure of a [rule response](https://github.com/kubescape/opa-utils/blob/master/reporthandling/datastructuresv1.go#L23)


4. Add a test for the new rule (and run it!). Learn how to add a test [here](testrunner/README.md#adding-new-rules) and how to run it [here](testrunner/README.md).

5. Add `filter.rego` if needed - If it exists, the filter is run by Kubescape to calculate ‘all resources’ = the number of potential resources to fail. It affects the risk score. This is needed in cases where a rule asks for resources that wil not potentially fail. Example: if a rule asks for pods and service accounts to see if they are connected but only fails the pods, we would create a filter rego that returns only pods.

**N.B.** To speed up the rule creation, we provided the script `scripts/init-rule.py`. This tool for scaffolding and code generation can be used to bootstrap a new rule fast. Let's see an example. To create a new rule, type the command:

```shell
python3 scripts/init-rule.py \
    --name "ensure-something-is-set" \
    --fix-command "chmod 700 /tmp/file" \
    --rule-description "this is an example description" \
    --rule-remediation "this is an example remediation" \
    --alert-message "found something weird" \
    --test-list "success,failed_1,failed_2"
```

This command will create the following directory structure in the **regolibrary** repository.

```shell
rules/ensure-something-is-set/
├── raw.rego
├── rule.metadata.json
└── test
    ├── failed_1
    │   ├── expected.json
    │   └── input
    ├── failed_2
    │   ├── expected.json
    │   └── input
    └── success
        ├── expected.json
        └── input
```

To have a complete overview about the script, type this command: `python3 scripts/init-rule.py --help`.

## OPA bundles
The Kubescape regolibrary is [available](https://github.com/kubescape/regolibrary/releases/latest) as an [OPA bundle](https://www.openpolicyagent.org/docs/latest/management-bundles), for both targets, WASM and Rego. 

### Using the bundles
> Endpoint names are normalized to be used as a Rego package name. Here are some examples:
> ```
> host-pid -> host_pid
> Host_Ipc -> Host_Ipc
> foobar -> foobar
> ```
> To be sure, you can use the following regex to validate the endpoint name:
> ```python
> import re
> def normalize_rule_name(name) -> str:
>      return re.sub(r'[^a-zA-Z0-9_]', '_', name)
> ```

#### Rules
Rules endpoints uses the following naming convention:
```
data.armo_builtins.rules.<rule_name>.raw.deny
```
If there is a filter rule, it's available at the following endpoint:
```
data.armo_builtins.rules.<rule_name>.filter.deny
```
#### Controls
Controls endpoints uses the following naming convention:
```
data.armo_builtins.controls.<control_id>.deny
```
#### Frameworks
Frameworks endpoints uses the following naming convention:
```
data.armo_builtins.frameworks.<framework_name>.deny
```

### Settings
When evaluating frameworks or controls, you can control the amount of metadata the results will contain by using the `data.settings`.

Available settings:
- `data.settings.verbose`: If set to `true`, the evaluation will return a list with an entry for each rule response. Each rule response includes the rule response itself, the control metadata (if evaluated as part of a control), and the framework metadata (if evaluated as part of a framework).

- `data.settings.metadata`: If set to `true`, the evaluation will return a json object with the metadata of the rule, the control (if evaluated as part of a control), or the framework (if evaluated as part of a framework). This json object will have a field named `"results"`, with all the lower level results.

  When `data.settings.verbose` was set to `true`, it takes precedence over `data.settings.metadata`.

  Here is an example of a framework evaluation using the `data.settings.metadata` setting:
  ```json5
  {
    "name": "ArmoBest",
    "controlsNames": [...],
    "description": "",
    // Other framework metadata ...
    "results": {
      "C-0005": {
        "name": "API server insecure port is enabled",
        "controlID": "C-0005",
        // Other control metadata ...
        "results": [
          {
            "alertMessage": "API server insecure port is enabled",
            // Other rule response fields ...
          }
        ]
      }
    }
  }
  ```
- No settings: If no settings were set, the evaluation will return a list with an entry for each rule response. Each rule response will include only the rule response itself.
> The default setting in the released bundles is `data.settings.metadata`.

### Build
To build the OPA bundles, use the python script `/scripts/bundle.py`.

For example:
```bash
python3 scripts/bundle.py . -o release
```

### Unsupported rules and controls
Some rules and controls are not supported in the OPA bundles, because they require extra customized Rego built-in functions (you can always use Kubescape to evaluate them :wink:).

#### Rules
The following rules are not supported in the OPA bundles:
<!-- Start of OPA bundles removed rules -->
- deny-RCE-vuln-image-pods
- exposed-rce-pods
- has-critical-vulnerability
- deny-vuln-image-pods
- rule-can-bash-cmd-inside-container
- excessive_amount_of_vulnerabilities_pods
- exposed-critical-pods
<!-- End of OPA bundles removed rules -->

## Support & Communication
Reach out if you have any questions:

* [Open an issue](https://github.com/kubescape/regolibrary/issues/new/choose)
* [Slack Community ](https://cloud-native.slack.com/archives/C04EY3ZF9GE) For any Q&A or support you can reach us at our CNCF Slack channels


## Learn more: 
- [NSA Framework](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)

- [MITRE ATT&CK® Framework](https://www.microsoft.com/security/blog/wp-content/uploads/2021/03/Matrix-1536x926.png)

- [CIS Framework](https://workbench.cisecurity.org/benchmarks/8973)

## Contributions

Thanks to all our contributors! Check out our [CONTRIBUTING](https://github.com/kubescape/kubescape/blob/master/CONTRIBUTING.md) file to learn how to join them.

* Feel free to pick a task from the [issues](https://github.com/kubescape/regolibrary/issues?q=is%3Aissue+is%3Aopen+label%3A%22open+for+contribution%22), roadmap or suggest a feature of your own.
* [Open an issue](https://github.com/kubescape/regolibrary/issues/new/choose): we aim to respond to all issues within 48 hours.
* [Join the CNCF Slack](https://slack.cncf.io/) and then our [users](https://cloud-native.slack.com/archives/C04EY3ZF9GE) or [developers](https://cloud-native.slack.com/archives/C04GY6H082K) channel.
