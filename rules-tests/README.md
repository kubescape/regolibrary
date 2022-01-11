# Adding new rules


When adding a new rule, create a test for it.  
All tests are run upon pushing, please make sure they all pass.    
This mechanism will aggregate resources accordingly, and get the default config inputs as input automatically.  
Currently, tests compare the `k8sApiObjects`, `externalObjects`, `failedPaths`, and `RuleStatus` fields.

## How to create a test
<br />

1 - Browse into `rule-tests` directory.  
2 - Create a new folder with the same name as the rule to be tested  
3 - Inside this folder, create a new folder for your test (arbitrary name), and browse into it    
4 - Create a file name `expected.json` and put the expected response
5 - Create a folder name `input` and put the files which are the input for the test (yaml/json)  
6 - That's it. The test will run using the rego and metadata.json from the `rules` file, using what's inside the `input` folder as input

You can create as many tests as you wish

## Debugging your tests
<br />

Inside the `rego_test.go` file, in the `testrunner` directory, you can run tests from a specific directory using the `TestSingleRule` function. Just change the variable `dir` to the name of your test folder.
<br />  
For running a single regoe locally, you can use the `TestSingleRego` function. It will take as input the files inside the `input` folder, in the `test-single-rego` directory. Just change the `testDir` variable to the name of your test. The result will be printed.  
So no more need for rego playground, and this is especially helpful when using aggregation