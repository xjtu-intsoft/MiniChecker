# MiniChecker

MiniChecker is a tool for detecting abusive data permission request behaviors in mini-programs, which is implented MiniChecker base on [Codefuse-Query](https://github.com/codefuse-ai/CodeFuse-Query). This work has been accepted by 39th IEEE/ACM International Conference on Automated Software Engineering (ASE 2024). For more implementation details, please refer to our paper.

## Table of contents

- [MiniChecker](#minichecker)
  - [Table of contents](#table-of-contents)
  - [Environment](#environment)
  - [Structure](#structure)
  - [Benchmark](#benchmark)
  - [Usage](#usage)
  - [Example](#example)
  - [Citation](#citation)

## Environment
* Java 8 for Codefuse-Query
* Codefuse-Query (local version or server version)
* Python 3.9.6

## Structure
* compare: comparative experiment code
* basic-query.gdl:  main script using *Codefuse-Query* to query code information
* checker-local.py: main script using *Python* to compute and match the features of different risks
* util.py: self-defined library function
* checker-patch.py: script for patch analsis
* benchmark.zip: benchmark cases for abusive permission request risks. 

## Benchmark

> Note: We have actively made efforts to make *MiniChecker* publicly accessible to improve the reusability of our artifacts. However, due to confidentiality constraints imposed by some of the platforms we collaborate with, the full content of benchmark codes are not allowed to be disclosed. We have tried our best to enhance the availability of our artifact, desensitized the analyzed data and integrated the risk behavior fragment code into the following basic code fragment.

* overlay/single1: Simple example, loading two APIs simultaneously in the lifecycle function launched by app.js
* overlay/single2: Simple example, loading two APIs simultaneously in the lifecycle function launched on the page
* overlay/lifecycle1: Complex example, loading two APIs separately in different lifecycle functions on the page
* overlay/lifecycle2: Complex example, loading one at app.js startup and one at page startup, with an import introduction module
* bother/no-condition: Simple example, determining the condition without a state before calling the API
* bother/no-fail-callback: Simple example, no failure callback after calling the API
* bother/no-update: Simple example, a failed callback to the API does not affect the result of conditional judgment
* loop/recursion1: Simple example, caused by simple recursion of a function
* loop/recursion2: Complex example, recursion caused by callback failure of authorization function, authorization API can only terminate with consent
* loop/recursion3: Complex example, recursion caused by external functions carrying authorization functions recursively, regardless of API agreement. This recursive loop will not terminate
* loop/recursion4: Simple example, recursive loop of functions caused by events
* loop/autojump1: Simple example, there is automatic jumping between pages and automatic authorization behavior on the target page
* loop/autojump2: Complex example, after rejecting authorization, a prompt pops up, the user only has one consent option, and there is an automatic jump between pages
* repeat/event1: Complex example, executing two APIs of the same type consecutively (event-callback) 
* repeat/event2: Complex example, executing two APIs of the same type consecutively (lifecycle-event)

## Usage

**Step 1: Create the database using *CodeFuse* tool**

**Command execution**

```bash
$CodeFusePath database create -t=JavaScript,XML -s=$PackageSource Dir $-log=ALL $DatabaseOutputDir
```

**Parameter Introduction**

* `CodeFusePath`: The address of the CodeFuse tool, such as `/workpath/CodeFuse-cli-server/CodeFuse`

* `PackageSourceDir`: The directory of the mini program source code, such as `/workpath/data/$miniprogramname/dist`

* `DatabaseOutputDir`: Output the directory where the database is stored, such as `/workpath/data/$miniprogramname/db`

> During the analysis process, in addition to analyzing the JavaScript code, the analysis and construction function of XML was also used. Losing this part of the database can cause query errors.

> When building the database, it is possible to exclude nodes as needed_ Modules and other irrelevant libraries reduce the size of the database to accelerate analysis.



**Step 2: Query basic information using *CodeFuse* and mini-program database**

**Command execution**

```bash
$CodeFusePath query run -d=$DatabaseOutputDir -f=json -o $QueryResultOutputDir $QueryScriptPath
```

**Parameter Introduction**

* `CodeFusePath`: The address of the CodeFuse tool

* `DatabaseOutputDir`: The directory where the output database is stored

* `QueryResultOutputDir`: The address to output the query result, such as `/workpath/data/$miniprogramname/output`

* `QueryScriptPath`: Query script address, such as `/$workpath/script/basic-query.gdl`


**Step 3: Run *MiniChecker* to detect abusive permission request risks**

**Command execution**

```bash
$PythonPath $AnalyzeScriptPath $PackageSourceDir $SavePath$
```

* `PythonPath`: The address of a Python tool, such as `/$workpath/bin/Python`

* `AnalyzeScriptPath`: The address of the analysis script, such as `/workpath/script/checker-local.py`

* `PackageSourceDir`: The address of the mini-program directory

* `SavePath`: The address where the risk results are stored

> This step connects to the script query results. To run the local version, it is necessary to obtain information from the `app.json` directory in the mini program directory, so the mini-program directory address needs to be entered. 



## Example

```
{
  "riskId": 0,
  "riskType": "PopUp Overlap Caused by Event",
  "riskInfo": {
      "path": "c/e8/n1/n.js",
      "callName": "joinMemberByAuth",
      "branchInEncapsulation": [
          {
              "branchLoc": 184,
              "branchCondition": "authValid",
              "branchVariable": "authValid"
          }
      ],
      "popUpList": [
          {
              "callName": "joinMemberByAuth",
              "path": "c/e8/n1/n.js",
              "loc": 272,
              "branch": [
                {
                      "branchLoc": 103,
                      "branchCondition": "status === 400 && data",
                      "branchVariable": "data"
                }
              ],
              "failCallback": "",
              "eventOpenType": "getPhoneNumber"
          },
          {
              "callName": "my.getAuthCode",
              "path": "c/e8/n1/n.js",
              "loc": 309,
              "branch": [],
              "failCallback": "NO_FAIL_CALLBACK",
              "eventOpenType": "NO_OPEN_TYPE"
          }
      ],
      "eventAttribute": "onTap",
      "event": true
  },
  "possible": false
}

```


## Citation

If you find MiniChecker useful, please consider citing our paper :)

  
