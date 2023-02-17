# Test-Runner for Rego Rules

This package tests the OPA Rego rules.

# Running the tests
You can easily test your custom rules by running this command:

```shell
go test -v -tags=static rego_test.go -run TestAllRules
```

or simply:

```shell
make test
```

If you want to test only a single rule, then you should use this command instead:

```shell
go test -v -tags="static" rego_test.go -run TestSingleRule -args -rule <rule-name>
```

Example:

```shell
go test -v -tags="static" rego_test.go -run TestSingleRule -args -rule ensure-azure-rbac-is-set
```

# VS code configuration samples

You can use the sample files below to setup your VS code environment for debugging purposes.

```json5
// .vscode/settings.json
{
    "go.testTags": "static",
    "go.toolsEnvVars": {
        "CGO_ENABLED": "1"
    }
}
```
```json5
// .vscode/launch.json
{
    "name": "Launch test function",
    "type": "go",
    "request": "launch",
    "mode": "test",
    "program": "${workspaceFolder}/rego_test.go",
    "buildFlags": "-tags=static",
    "args": [
        "-test.run",
        "TestAllRules"
    ]
}
```

# Adding new rules


When adding a new rule, create a test for it.  
All tests are run upon pushing, please make sure they all pass.    
This mechanism will aggregate resources accordingly, and get the default config inputs as input automatically.  
Currently, tests compare the `k8sApiObjects`, `externalObjects`, `failedPaths`, and `RuleStatus` fields.  
To run all tests:  `cd testrunner/ && go test -v rego_test.go -run TestAllRules`

## How to create a test
<br />

1 - Create a new folder `test` in your new rule directory.   
2 - Inside this folder, create a new folder for your test (arbitrary name), and browse into it    
3 - Create a file name `expected.json` and put the expected response  
4 - Create a folder name `input` and put the files which are the input for the test (yaml/json)  
5 - That's it. The test will run using the rego and metadata.json, and using what's inside the `input` folder as input

You can create as many tests as you wish

## Debugging your tests
<br />

Inside the `rego_test.go` file, in the `testrunner` directory, you can run tests from a specific directory using the `TestSingleRule` function. Just change the variable `dir` to the name of your test folder.
<br />  
For running a single regoe locally, you can use the `TestSingleRego` function. It will take as input the files inside the `input` folder, in the `test-single-rego` directory. Just change the `testDir` variable to the name of your test. The result will be printed.  
So no more need for rego playground, and this is especially helpful when using aggregation
