[NOTE] Due to the Anonymous GitHub mechanism, certain Markdown files might appear blank for display reasons. Here, we provide the raw text version for the reviewers' direct reference.

# MiniChecker

MiniChecker is a tool for detecting abusive data permission request (ADPR) behaviors in mini-programs.

We implented MiniChecker base on *Sparrow*  (from [Code-Fuse](https://github.com/codefuse-ai/CodeFuse-Query)).

**As of December 16, 2023, we are actively working towards making *MiniChecker* publicly available to enhance the reusability of our artifacts. However, due to confidentiality constraints imposed by some of the platforms we collaborate with, the code and data in our artifacts must undergo de-identification and review by these platforms before the full content of MiniChecker can be disclosed. Upon completion of the review process, we will promptly release the entire method code.**


## Table of contents

- [Dependency](#dependency)
- [Structure](#structure)
- [Benchmark](#benchmark)
- [Usage](#usage)
- [Example](#example)
- [License](#license)

## Dependency
* Java 8 for *Sparrow* 
* *Sparrow* (local version or server version)
* Python 3.9.6

## Structure
* /benchmark: benchmark cases for four ADPR risks
* basic-query.gdl:  main script using *Sparrow* to query code information
* checker-local.py: main script using *Python* to compute and match the features of different risks
* util.py: self-defined library function
* checker-patch.py: script for patch analsis

## Benchmark

Due to data security limitations, we have desensitized the analyzed data and integrated the risk behavior fragment code into the following basic code fragment.

* overlay/single1: Simple example, loading two APIs simultaneously in the lifecycle function launched by app. js
* overlay/single2: Simple example, loading two APIs simultaneously in the lifecycle function launched on the page
* overlay/lifecycle1: Complex example, loading two APIs separately in different lifecycle functions on the page
* overlay/lifecycle2: Complex example, loading one at app. js startup and one at page startup, with an import introduction module
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

### Step 1: Create the database using *Sparrow* tool

**Command execution**

`$SparrowPath $database create - t=JavaScript, XML - s=$PackageSource Dir $- log=ALL $Database OutputDir$`

**Parameter Introduction**

* $SparrowPath$: The address of the Sparrow tool, such as "/$workpath/sparrow-li-server/sparrow"

* $PackageSourceDir$: The directory of the mini program source code, such as "/$workpath/data/$miniprogramname/dist"

* $DatabaseOutputDir$: Output the directory where the database is stored, such as "/$workpath/data/$miniprogramname/db"

**Remarks**

* During the analysis process, in addition to analyzing the JavaScript code, the analysis and construction function of XML was also used. Losing this part of the database can cause query errors.

* When building the database, it is possible to exclude nodes as needed_ Modules and other irrelevant libraries reduce the size of the database to accelerate analysis.



### Step 2: Query basic information using *Sparrow* and mini-program database

**Command execution**

`$SparrowPath $query run - d=$DatabaseOutputDir $- f=json - o $QueryResultOutputDir $$QueryScriptPath$`

**Parameter Introduction**

* $SparrowPath$: The address of the Sparrow tool

* $DatabaseOutputDir$: The directory where the output database is stored

* $QueryResultOutputDir$: The address to output the query result, such as "/$workpath/data/$miniprogramname/output"

* $QueryScriptPath$: Query script address, such as "/$workpath/script/basic-query.gdl"


### Step 3: Run *MiniChecker* to detect ADPR risks

**Command execution**

`$PythonPath $AnalyzeScriptPath $PackageSourceDir $SavePath$`

* $PythonPath$: The address of a Python tool, such as "/$workpath/bin/Python"

* $AnalyzeScriptPath$: The address of the analysis script, such as /$workpath/script/checker-local.py"

* $PackageSourceDir$: The address of the mini-program directory

* $SavePath$: The address where the risk results are stored

**Remarks**

This step connects to the script query results. To run the local version (checker-local.py), it is necessary to obtain information from the app.json directory in the mini program directory, so the mini program directory address needs to be entered. 



## Example

**Output results**

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

## License


  
