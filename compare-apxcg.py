import os
import subprocess
import shutil
import json
import pandas
from ASEMiniChecker import App

recordPath = "..."
baselineDir = "..."
def generateCG(appName):
    appDir = "..." % appName
    appSave = "...s" % appName

    if os.path.exists(appSave):
        shutil.rmtree(appSave)

    os.mkdir(appSave)

    totalFile = 0
    sucFile = 0
    for root, dirs, files in os.walk(appDir):
        for f in files:
            if f.endswith(".js"):
                totalFile += 1
                try:
                    fileDir = os.path.join(root, f)
                    relativeDir = fileDir.replace(appDir, "")
                    cmd = " ".join(["js-callgraph --cg", fileDir , "--output", os.path.join(appSave, relativeDir.replace("/", "_").replace(".js", ".json"))])

                    p = subprocess.Popen(cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                    )
                    p.wait(300)

                    # print(p.poll())
                    if p.poll() == 0:
                        sucFile = sucFile + 1 
                        print(os.path.join(root, f))               
                except Exception as e:
                    print(e)

    print(appName, sucFile, totalFile)
    open(recordPath,"a").write("%s, %s, %s\n" % (appName, sucFile, totalFile))


def transResultToCheckerFormat(appName):
    print("---%s---" % appName)
    # transform to minichecker
    formatResult = {
        "queryAuthorizeAPI": [],
        "queryAuthorizeEvent": [],
        "queryAlertAPI": [],
        "queryRouteAPI":[],
        "queryXMLEvent": [],
        "queryXMLImport": [],
        "queryXMLTemplate": [],
        "queryRequestAPI": [],
        "queryFunctionAndMethod": [],
        "queryBranchAndCondition": [],
        "queryGetAppCallFunction": [],
        "queryFunctionContainsCall": [],
        "queryCallbackContainsCall": [],
        "queryThisKeywordRelatedCall": [],
        "queryExport": [],
        "queryImport": []
    }

    callNodeList = []
    def addCallNode(newCallNode):
        for cn in callNodeList:
            if cn["callName"] == newCallNode["callName"] and cn["callLoc"] == newCallNode["callLoc"] and cn["path"] == newCallNode["path"]:
                return cn["callId"]
        
        callId = len(callNodeList)
        callNodeList.append({
            "path": newCallNode["path"],
            "callName": newCallNode["callName"],
            "callLoc": newCallNode["callLoc"],
            "callId": callId
        })
        return callId
    # apxjs can not locate api, here we use the authorize api location result generated from minicheckers
    qresResultFile = os.path.join("...", "qres-%s.json" % appName)
    qresContent = json.load(open(qresResultFile, "r", encoding="utf-8"))
    for an in qresContent["queryAuthorizeAPI"]:
        anid = addCallNode({
            "path": an["path"],
            "callName": an["callName"],
            "callLoc": an["callLoc"],
        })

        newNode = {
            "path": an["path"],
            "callName": an["callName"],
            "callLoc": an["callLoc"],
            "callId": anid,
            "successCallback": "NO_SUCCESS_CALLBACK",
            "failCallback": "NO_FAIL_CALLBACK",
            "scope": "NO_SCOPE"
        }
        if str(newNode) not in formatResult["queryAuthorizeAPI"]:
            formatResult["queryAuthorizeAPI"].append(newNode)

        newNode = {
            "path": an["path"],
            "callName": an["callName"],
            "callLoc": an["callLoc"],
            "callId": an["callLoc"],
            "callType": "use"
        }
        if str(newNode) not in formatResult["queryFunctionAndMethod"]:
            formatResult["queryFunctionAndMethod"].append(newNode)


    for fcc in qresContent["queryFunctionContainsCall"]:
        if "my." in fcc["callName"]:
            cid = addCallNode({
                "path": fcc["path"],
                "callName": fcc["callName"],
                "callLoc": fcc["callLoc"]
            })

            mid = addCallNode({
                "path": fcc["path"],
                "callName": fcc["methodName"],
                "callLoc": fcc["methodLoc"]
            })

            formatResult["queryFunctionContainsCall"].append({
                "path": fcc["path"],
                "callName": fcc["callName"],
                "callLoc": fcc["callLoc"],
                "callId": cid,
                "methodName": fcc["methodName"],
                "methodLoc": fcc["methodLoc"],
                "methodId": mid
            })
 
    resultDir = os.path.join(os.path.join(baselineDir, appName, "apxjs"))
    distPath = os.path.join(os.path.join(baselineDir, appName, "dist"))
    for rf in os.listdir(resultDir):
        resFileContent = json.load(open(os.path.join(resultDir, rf), "r", encoding="utf-8"))
        for item in resFileContent:
            sourceFunc = item["source"]
            sourceFuncPath = os.path.relpath(sourceFunc["file"], distPath)

            sinkFunc = item["target"]
            sinkFuncPath = os.path.relpath(sinkFunc["file"], distPath)

            sourceId = addCallNode({
                "path": sourceFuncPath,
                "callName": sourceFunc["label"],
                "callLoc": sourceFunc["start"]["row"],
            })

            sinkId = addCallNode({
                "path": sinkFuncPath,
                "callName": sinkFunc["label"],
                "callLoc": sinkFunc["start"]["row"],
            })


            newFCCNode = {
                "path": sourceFuncPath,
                "callName": sourceFunc["label"],
                "callLoc": sourceFunc["start"]["row"],
                "callId": sourceId,
                "methodName": sinkFunc["label"],
                "methodLoc": sinkFunc["start"]["row"],
                "methodId": sinkId,
            }

            if str(newFCCNode) not in formatResult["queryFunctionContainsCall"]:
                formatResult["queryFunctionContainsCall"].append(newFCCNode)
        
            
    outDir = "...."
    outputJson = os.path.join(outDir, "%s_apxjs.json" % appName)
    json.dump(formatResult ,open(outputJson, "w", encoding="utf-8"), ensure_ascii=False)


def analyze(aname):
    appDistPath = os.path.join("...", aname, "dist")
    outputPath = "..."
    apxjsCG = os.path.join("...", )
    # 执行分析命令
    app = App(
        id=aname,
        dist=appDistPath,
        db="",
        output=outputPath)
    app.queryPopUpRisk(existQueryResult=os.path.join(outputPath, aname + "_apxjs.json"))
    app.outputRisk()


def outputResult():
    labelCsv = "..."
    riskDir = "..."
    labelList = []
    for riskFile in os.listdir(riskDir):
        if "risk" in riskFile:
            riskContent = json.load(open(os.path.join(riskDir, riskFile), "r"))

            appName = riskFile.removeprefix("risk-").removesuffix(".json")
            riskList = [False, False, False, False, False]

            for risk in riskContent:
                for rtIndex, rt in enumerate(["First Page", "Overlay", "Bother", "Repeat", "Loop"]):
                    if rt in risk["riskType"]:
                        riskList[rtIndex] = True
            print(riskList)

            labelList.append({
                "appName_zh": appName, 
                "appName_en": "",
                "homepage": riskList[0],
                "overlay": riskList[1],
                "bother": riskList[2],
                "repeat": riskList[3],
                "loop": riskList[4]
            })

            labelPd = pandas.DataFrame.from_dict(labelList)
            # columns=["appName", "appName", "homepage", "overlay", "bother", "repeat", "loop"]
            labelPd.to_csv(labelCsv, index=False)

def patchAnalyze():
    for idx, app in enumerate(os.listdir(baselineDir)):
        if not "DS_Store" in app:
            # print("---" + app + "---")
            outDir = "..."
            outputJson = os.path.join(outDir, "%s_apxjs.json" % app) 

            # if os.path.exists(outputJson):
            #     continue

            # generateCG(appName=app)
            transResultToCheckerFormat(app)


def singleAnalyze():
    for idx, app in enumerate(os.listdir(baselineDir)):
        if not "DS_Store" in app:
            
            transResultToCheckerFormat(app)
            analyze(app)


# singleAnalyze()
# outputResult()
