# 此文件用于分析是否存在弹窗相关违规问题

import os
import json
import shutil
import extendUtilForAse as extendUtil
import time
import pandas as pd
import copy
import sys
import tqdm

basePath = "..."
sparrowPath = "..."
# outputPath = "..."
queryScriptPath = "..."

class App:
    def __init__(self, id, dist="", db="", output="") -> None:
        # 本地检测版本
        # dist: 小程序源码目录
        # db: 数据库目录
        self.absolutePath = dist
        if db:
            self.dbPath = db
        if output:
            self.outputPath = output
        self.getPagesList()
        self.risks = []
        self.riskCount = {"overlay": 0, "bother": 0, "repeat":0, "loop": 0}
        # self.appName = self.dbPath.replace(basePath, "").replace("/", "").replace("db", "")
        self.appID = id

        # 清零debug文件
        open(os.path.join(self.outputPath, "debug-%s.txt" % self.appID), "w").write("")
    
    def generateDB(self):
        if 1:
            os.system(" ".join([sparrowPath, "database", "create", "-t=javascript,xml","-s=%s"%self.absolutePath,"-log=ALL",self.dbPath]))
        
    def runQuery(self):
        if 1: 
            os.system(" ".join([sparrowPath, "query", "run", "-d=%s"%self.dbPath,"-f=json","-o",self.outputPath, queryScriptPath]))
            outputFile = os.path.join(self.outputPath, os.path.basename(queryScriptPath).replace(".gdl",".json"))
            if os.path.exists(outputFile):
                newName = os.path.join(self.outputPath, "qres-%s.json"%self.appID)
                os.rename(outputFile, newName)
            print("Sparrow Run Success.")

    # ***** 导入分析结果 *****

    def loadQueryResult(self, queryResult):
        # 导入分析结果
        if queryResult:
            self.qresPath = queryResult
        else:
            self.qresPath = os.path.join(self.outputPath, "qres-%s.json"%self.appID)
        self.queryResult = json.load(open(self.qresPath, "r", encoding="utf-8"))

        # # 过滤文件
        # newResult = {}
        # # 判断是否为混淆小程序
        # fileFunctionDefineUseCountDict = {}
        # for i in self.queryResult["queryFunctionAndMethod"]:
        #     if i["path"] not in fileFunctionDefineUseCountDict:
        #         fileFunctionDefineUseCountDict[i["path"]] = 1
        #     else:
        #         fileFunctionDefineUseCountDict[i["path"]] += 1
        
        # highFrequencyDefineFileNum = 0
        # for f in fileFunctionDefineUseCountDict:
        #     if fileFunctionDefineUseCountDict[f] > 50:
        #         highFrequencyDefineFileNum += 1
        
        # # 是混淆，返回空
        # if highFrequencyDefineFileNum > 0.5 * len(fileFunctionDefineUseCountDict):
        #     print("This is a obfuscated mini program.")
        #     for key in self.queryResult.keys():
        #         newResult[key] = []  
        # else:
        #     # 不是混淆，过滤库文件
        #     for key in self.queryResult.keys():
                
        #         newContent = []
        #         for item in self.queryResult[key]:
        #             if "path" in item.keys() and self.inBlackFileList(item["path"]):
        #                 continue

        #             newContent.append(item)
    
        #         newResult[key] = newContent.copy()
                
        # self.queryResult = newResult

    def inBlackFileList(self, filePath):
        # 是否在黑名单列表中
        if filePath in ["common/vendor.js"]:
            return True
        if "node-modules/" in filePath or "npm/" in filePath or "node_modules/" in filePath:
            return True
        
        return False
    
    # ***** 基本分析 *****  
      
    def getPagesList(self):
        self.appJsonAbsolutePath = os.path.join(self.absolutePath, "app.json")
        # print(self.appJsonAbsolutePath)
        if not os.path.exists(self.appJsonAbsolutePath):
            print("[WARNING] app.json not found.")
            self.appJsonPagesList = []
            self.appJsonFirstPageRelativePath = "_NO_JSON_"
        else:
            self.appJsonContent = json.load(open(self.appJsonAbsolutePath, "r", encoding="utf-8"))
            self.appJsonPagesList = self.appJsonContent["pages"]
            self.appJsonFirstPageRelativePath = self.appJsonPagesList[0] + ".js"
        print("Get first page -> %s" % self.appJsonFirstPageRelativePath)
    
    def buildTaintedCallGraph(self):
        print(">>> Build taint function graph ...")
        # 构建污点弹窗函数的传播流图
        # self.funcNodes = []
        # self.funcEdges = []

        # 函数关联分析
        if "queryFunctionAndMethod" in self.queryResult:
            
            # 构建函数关联关系
            self.funcEdges = extendUtil.buildFunctionReference(self.queryResult, self.absolutePath)
            # 补充函数调用的触发分支信息
            self.funcNodes = extendUtil.updateBranchInfo(self.queryResult)
            # 补充函数调用的节点和边关联关系，用于搜索遍历
            # self.funcNodes, self.funcEdges = extendUtil.updateGraphRelationInfo(nodes = self.funcNodes, edges = self.funcEdges)

            # 关注的污点函数类型：授权，用户行为（弹窗提示）
            taintedKeys = ["authorize", "alert", "route"]
            # 初始化污点传播标记
            for n in self.queryResult["queryFunctionAndMethod"]:
                # 授权弹窗/提示弹窗/页面跳转/传输请求
                for taintedKey in taintedKeys:
                    n[taintedKey + "Tainted"] = False
                    n[taintedKey + "InitTainted"] = False
                    n[taintedKey + "TaintedBy"] = []    

            # 为API调用进行标记，包括：授权弹窗/提示弹窗/页面跳转/传输请求
            for taintedKey in taintedKeys:
                for popup in self.queryResult["query" + taintedKey.capitalize() + "API"]:
                    for n in self.queryResult["queryFunctionAndMethod"]:
                        if n["callId"] == popup["callId"]:
                            n[taintedKey + "InitTainted"] = True
                            n[taintedKey + "Tainted"] = True
                            n["failCallback"] = popup["failCallback"]

                            if n["callId"] not in n[taintedKey + "TaintedBy"]:
                                n[taintedKey + "TaintedBy"].append(n["callId"])
            
            # for nd in self.queryResult["queryFunctionAndMethod"]:
            #     # if nd["authorizeInitTainted"]:
            #     print(nd)

            # 为弹窗事件函数进行标记
            taintedEventFunctions = []
            for popupEvent in self.queryResult["queryAuthorizeEvent"]:    
                # 直接引用的事件
                for event in self.queryResult["queryXMLEvent"]:
                    if popupEvent["elementId"] == event["elementId"]:
                        taintedEventFunctions.append({
                            "callName": event["eventAttrValue"],
                            "elementPath": event["path"],
                            "pagePath": event["path"].replace(".axml", ".js"),
                            "sourceEvent": event
                        })
                # 通过template间接引用的事件
                for tpru in self.queryResult["queryXMLTemplate"]:
                    # 寻找模版的定义文件
                    # tpru: 使用处 -> ximp.path
                    # tprd: 定义处 -> ximp.referenceFile

                    tprdFile = extendUtil.getTemplateDefineFile(templateUse=tpru, queryResult=self.queryResult)
                    if tprdFile:
                        # print("[DEBUG]", tprdFile)
                        # 寻找模板组件是否有调用事件
                        for event in self.queryResult["queryXMLEvent"]:
                            if event["path"] == tprdFile:
                                taintedEventFunctions.append({
                                    "callName": event["eventAttrValue"],
                                    "elementPath": tpru["path"],
                                    "pagePath": tpru["path"].replace(".axml", ".js"),
                                    "sourceEvent": event
                                })

                if taintedEventFunctions:
                    for taintedEventFunction in taintedEventFunctions:
                        # print("[DEBUG]", taintedEventFunction)
                        for n in self.queryResult["queryFunctionAndMethod"]:
                            if n["callName"] == taintedEventFunction["callName"] \
                                and n["path"] == taintedEventFunction["pagePath"]:
                                n["authorizeInitTainted"] = True
                                n["authorizeTainted"] = True
                                n["failCallback"] = ""
                                n["eventOpenType"] = popupEvent["openType"]

                                # if n["callId"] not in n["authorizeTaintedBy"]:
                                #     n["authorizeTaintedBy"].append(n["callId"])

                    
            # 可选：近似污点传播，如通过getApp().POPUP调用的
            for possiblePopup in ["app.getUserAuth"]:
                for n in self.queryResult["queryFunctionAndMethod"]:
                    if possiblePopup == n["callName"]:
                        n["authorizeInitTainted"] = True
                        n["failCallback"] = ""
                        n["authorizeTainted"] = True

                        if n["callId"] not in n["authorizeTaintedBy"]:
                            n["authorizeTaintedBy"].append(n["callId"])

            # 污点传播
            # 批量运行时，如果节点过多，直接跳过 
            # if len(self.funcEdges) > 50000:
            #     self.taintedNodes = []
            #     print("[FAIL] Node Exceed Max Value.")
            # else:
            self.taintedNodes = extendUtil.taintSpread(
                nodes = self.queryResult["queryFunctionAndMethod"], 
                edges = self.funcEdges, 
                taintTypes = taintedKeys)

            print("[SUCCESS] Taint node spread success. All nodes: %d" % len(self.taintedNodes))

            # 更新污点函数的触发事件
            self.taintedNodes = extendUtil.getEventNode(nodes = self.taintedNodes, 
                                                            events = self.queryResult["queryXMLEvent"], 
                                                            eventRef = taintedEventFunctions)

            # for tn in self.taintedNodes:
            #     print(tn)

    def dividePopUpByLifecycle(self):
        for tn in self.taintedNodes:
            # 给授权相关的函数标记，自动触发还是事件触发
            tn["authorizeTriggerMethod"] = "unclear"           
            if tn["authorizeTainted"]:
                taintedByList = extendUtil.getNodeInfosByCallIdList(nodeIdList=tn["authorizeTaintedBy"], nodes=self.taintedNodes)

                if tn["path"] == "app.js" and tn["callName"] in ["onLoad", "onLaunch", "onShow", "onReady"]:
                    self.appLaunchPopUpList.append({
                        "path": tn["path"],
                        "callName": tn["callName"],
                        "branchInEncapsulation": tn["branch"],
                        "popUpList": taintedByList
                    })
                    tn["authorizeTriggerMethod"] = "active"

                if not tn["path"] == "app.js" and tn["callName"] in ["onLoad", "onLaunch", "onShow", "onReady"]:
                    self.pageLaunchPopUpList.append({
                        "path": tn["path"],
                        "callName": tn["callName"],
                        "branchInEncapsulation": tn["branch"],
                        "popUpList": taintedByList
                    })
                    tn["authorizeTriggerMethod"] = "active"

                if tn["event"]:
                    # print("[DEBUG]", tn)
                    self.eventPopUpList.append({
                        "path": tn["path"],
                        "callName": tn["callName"],
                        "branchInEncapsulation": tn["branch"],
                        "popUpList": taintedByList,
                        "eventAttribute": tn["event"]["eventAttrName"]
                    })
                    tn["authorizeTriggerMethod"] = "passive"

        outputPopupInfo = ""
        outputPopupInfo += "--- App Launch Popup ---\n"
        for idx, p in enumerate(self.appLaunchPopUpList):
            outputPopupInfo += "[%s] %s \n" %(idx,p)

        outputPopupInfo += "--- Page Popup ---\n"
        for idx, p in enumerate(self.pageLaunchPopUpList):
            outputPopupInfo += "[%s] %s \n" %(idx,p)

        outputPopupInfo += "--- Event Popup ---\n"
        for idx, p in enumerate(self.eventPopUpList):
            outputPopupInfo += "[%s] %s \n" %(idx,p)

        open(os.path.join(self.outputPath, "debug-%s.txt" % self.appID), "a").write(outputPopupInfo)


    def getFirstPagePopUp(self):
        for alp in self.appLaunchPopUpList:
            # 小程序启动时弹窗
            launchRisk = {
                "riskId": len(self.risks),
                "riskType": "PopUp in First Page",
                "riskInfo": copy.deepcopy(alp)
            }
            self.risks.append(launchRisk)
        
        for plp in self.pageLaunchPopUpList:
            # 在json中标明的首页启动弹窗
            if plp["path"] == self.appJsonFirstPageRelativePath:
                launchRisk = {
                    "riskId": len(self.risks),
                    "riskType": "PopUp in First Page (Json)",
                    "riskInfo": copy.deepcopy(plp)
                }
                self.risks.append(launchRisk)

    # ***** 查询风险主入口 *****
        
    def queryPopUpRisk(self, riskType = ["homepage", "overlay", "bother", "loop", "repeat"], existQueryResult=None):
        print(">>> Load codebase ...")
        self.loadQueryResult(queryResult = existQueryResult)

        beginTime = time.time()

        # 构建页面跳转流图
        print(">>> Build function call graph ...")
        self.buildPageRouteGraph()

        # 构建污点函数调用流图
        self.buildTaintedCallGraph()
        
        # 划分不同类型的弹窗函数：小程序加载弹窗、页面加载弹窗和事件弹窗
        self.appLaunchPopUpList = []
        self.pageLaunchPopUpList = []
        self.eventPopUpList = []
        # 
        self.dividePopUpByLifecycle()

        preprocessTime = time.time()

        # 小程序首屏弹窗
        if "homepage" in riskType:
            self.getFirstPagePopUp()
        
        homepageTime = time.time()

        # 弹窗叠加
        if "overlay" in riskType:
            print(">>> Now processing : overlay ...")
            self.queryPopUpOverlay()
            
        overlayTime = time.time()

        # 弹窗打扰
        if "bother" in riskType:
            print(">>> Now processing : bother ...")
            self.queryPopUpBother()
        
        botherTime = time.time()

        # 弹窗循环
        if "loop" in riskType:
            print(">>> Now processing : loop ...")
            self.queryPopUpLoop()
        
        loopTime = time.time()
        
        # 弹窗重复
        if "repeat" in riskType:
            print(">>> Now processing : repeat ...")
            self.queryPopUpRepeat()
        
        repeatTime = time.time()

        self.risks.append({
            "riskId": "-1",
            "riskType": "Status",
            "riskInfo":{
                "riskCount": self.riskCount,
                "preprocessTime": preprocessTime - beginTime,
                "homepageTime": homepageTime - preprocessTime,
                "overlayTime": overlayTime - homepageTime,
                "botherTime": botherTime - overlayTime,
                "loopTime": loopTime - botherTime,
                "repeatTime": repeatTime - loopTime
            }
            
        })
    
    def buildPageRouteGraph(self):
        # 构建页面跳转流图
        # self.pageNodes = []
        # self.pageEdges = []

        # 页面跳转关系构建
        if "queryRouteAPI" in self.queryResult:
            # 根据路由API确定页面跳转关系
            self.pageNodes, self.pageEdges = extendUtil.buildPageReference(
                nodeInfo = self.appJsonPagesList, 
                edgeInfo = self.queryResult["queryRouteAPI"])
            # 根据事件组件确定发生跳转的位置
            self.pageEdges = extendUtil.eventLocate(
                nodes = self.pageNodes, 
                edges=self.pageEdges, 
                elements=self.queryResult["queryXMLEvent"])

    # ***** 弹窗叠加分析 *****

    def getAppLaunchPopUpOverlay(self):
        # 启动app.js的弹窗叠加
        for alp in self.appLaunchPopUpList: 
            if extendUtil.getDifferentCallNumber(alp["popUpList"], self.taintedNodes) > 1:
                triggerALP = copy.deepcopy(alp)
                triggerALP["event"] = False

                overlayRisk = {
                    "riskId": len(self.risks),
                    "riskType": "PopUp Overlay While Launching",
                    "riskInfo": triggerALP
                }
                self.risks.append(overlayRisk)
                self.riskCount["overlay"] += 1
           
    def getAppLaunchWithFirstPagePopUpOverlay(self):
        # 启动加载首页引起的弹窗叠加
        for alp in self.appLaunchPopUpList:
            for plp in self.pageLaunchPopUpList:          
                if plp["path"] == self.appJsonFirstPageRelativePath:
                    triggerALP = copy.deepcopy(alp)
                    triggerALP["event"] = False

                    for p1 in plp["popUpList"]:
                        for p2 in alp["popUpList"]:
                            if not p1["callName"] == p2["callName"]:
                                triggerALP["popUpList"].append(p1)

                    # print("[DEBUG1]", triggerALP["popUpList"])
                    # print(extendUtil.getDifferentCallNumber(triggerALP["popUpList"], self.taintedNodes))

                    if extendUtil.getDifferentCallNumber(triggerALP["popUpList"], self.taintedNodes) > 1:
                        overlayRisk = {
                            "riskId": len(self.risks),
                            "riskType": "PopUp Overlay in First Page",
                            "riskInfo": triggerALP
                        }
                        self.risks.append(overlayRisk)
                        self.riskCount["overlay"] += 1
                # else:
                #     print(plp["path"], self.appJsonFirstPageRelativePath)
    
    def getPagePopUpOverlay(self):
        # 页面弹窗叠加
        for plp in self.pageLaunchPopUpList:
            # 需要保证页面可达而非库文件
            if extendUtil.getDifferentCallNumber(plp["popUpList"], self.taintedNodes) > 1 \
                and plp["path"].replace(".js", "") in self.appJsonPagesList:
                triggerPLP = copy.deepcopy(plp)
                triggerPLP["event"] = False

                overlayRisk = {
                    "riskId": len(self.risks),
                    "riskType": "PopUp Overlay in Singal Page",
                    "riskInfo": triggerPLP
                }
                self.risks.append(overlayRisk)
                self.riskCount["overlay"] += 1
    
    def getEventPopUpOverlay(self):
        # 事件弹窗叠加
        for ep in self.eventPopUpList:
            if extendUtil.getDifferentCallNumber(ep["popUpList"], self.taintedNodes) > 1:
                triggerEP = copy.deepcopy(ep)
                triggerEP["event"] = True
                
                overlayRisk = {
                    "riskId": len(self.risks),
                    "riskType": "PopUp Overlay Caused by Event",
                    "riskInfo": triggerEP
                }
                self.risks.append(overlayRisk)
                self.riskCount["overlay"] += 1
    
    def getContinuousPopUpWhilePageLoad(self, taintList):
        # 为每个页面创建一个对象
        pageList = []
        for t in taintList:
            # 页面是否已经被访问过
            existPage = False
            for p in pageList:
                if p["path"] == t["path"]:
                    existPage = True
                
                    # 记录访问的页面加载函数
                    if t["callName"] not in p["pageLifeCycleFunction"]:
                        p["pageLifeCycleFunction"].append(t["callName"])

                    # 向已经访问过的页面添加弹窗函数
                    for popup in t["popUpList"]:
                        existPopUp = False
                        for alreadyExistPopup in p["popUpList"]:
                            if popup["callName"] == alreadyExistPopup["callName"]:
                                existPopUp = True
                        
                        if not existPopUp:
                            p["popUpList"].append(popup)

            # 为未访问的页面添加对象记录
            if not existPage:
                pageList.append({
                    "path": t["path"],
                    "popUpList": t["popUpList"],
                    "pageLifeCycleFunction": [t["callName"]],
                    "branchInEncapsulation": t["branchInEncapsulation"],
                })

        for p in pageList:
            if extendUtil.getDifferentCallNumber(p["popUpList"], self.taintedNodes) > 1 and len(p["pageLifeCycleFunction"]) > 1:
                overlayRisk = {
                    "riskId": len(self.risks),
                    "riskType": "PopUp Overlay Continuously Trigger While Load",
                    "riskInfo": {
                        "path": p["path"],
                        "callName": p["pageLifeCycleFunction"],
                        "branchInEncapsulation": p["branchInEncapsulation"],
                        "popUpList": p["popUpList"],
                    }
                }
                 
                self.risks.append(overlayRisk)
                self.riskCount["overlay"] += 1
    
    def getEventCombiningJsPopUpOverlay(self):
        return

    def queryPopUpOverlay(self):
        # 小程序启动弹窗叠加，在app生命周期中包含了两类不同类型的弹窗API
        self.getAppLaunchPopUpOverlay()
        # 小程序启动+首页叠加引起的弹窗叠加，在app生命周期中有1个API，在首页的生命周期函数中有1个API
        self.getAppLaunchWithFirstPagePopUpOverlay()
            
      
        # 页面启动弹窗，在单一启动函数中包含了两类不同类型的弹窗API
        self.getPagePopUpOverlay()
        # 页面启动弹窗，在多启动函数（如onLoad和onShow）包含了两类不同类型的弹窗API
        self.getContinuousPopUpWhilePageLoad(self.pageLaunchPopUpList)
        
        # 事件函数弹窗，Js内部叠加
        self.getEventPopUpOverlay()
        # 事件函数弹窗，Js+Xml叠加
        self.getEventCombiningJsPopUpOverlay()

    # ***** 弹窗循环分析 *****

    def getInPageFunctionReverseLoop(self):
        loops = extendUtil.findLoopsfromFuncGraph(nodes = self.funcNodes, edges = self.funcEdges)
        # print("Loops:", loops, self.appJsonPagesList)

        outputInfo = "---Function Loop---\n"
        for flId, fl in enumerate(loops):
            outputInfo += "[%s] %s\n" % (flId, fl)
        open(os.path.join(self.outputPath, "debug-%s.txt" % self.appID), "a").write(outputInfo)

        for tn in self.taintedNodes:
            if tn["authorizeTainted"]:
                taintedByList = extendUtil.getNodeInfosByCallIdList(nodeIdList=tn["authorizeTaintedBy"], nodes=self.taintedNodes)

                for l in loops:
                    if l["callId"] == tn["callId"] and tn["path"].replace(".js", "") in self.appJsonPagesList:
                        loopRisk = {
                            "riskId": len(self.risks),
                            "riskType": "PopUp Loop - Caused By Reverse",
                            "riskInfo": {   
                                "path": tn["path"],
                                "callName": tn["callName"],
                                "branchInEncapsulation": tn["branch"],
                                "popUpList": taintedByList,
                                "loop": l["loop"]
                            }
                        }

                        self.risks.append(loopRisk)
                        self.riskCount["loop"] += 1

    def getCrossPageNoConditionJumpLoop(self):
        # 无条件页面跳转
        self.noConditionJumpRoute = []

        # tn, 原始路由API触发点
        # tnn, 存在调用关系的路由行为触发点
        # 只有tn携带了路由信息，因此需要同时找到tn和tnn

        # 待更新：tn是否也应该直接处于生命周期呢？
        for tn in self.taintedNodes:
            for tnn in self.taintedNodes:    
                if tn["routeInitTainted"] and tnn["routeTainted"] and \
                    tnn["callName"] in ["onLoad", "onLaunch", "onShow", "onReady"] and \
                    tn["callId"] in tnn["routeTaintedBy"]:
            
                    # 找到路由在跳转流图中的边，确定跳转的目的页面
                    toPath = None
                    for pe in self.pageEdges:
                        if pe["callId"] == tn["callId"]:
                            fromPath = extendUtil.getPagePathByNodeId(id = pe["from"], pageNodes= self.pageNodes)
                            toPath = extendUtil.getPagePathByNodeId(id = pe["to"], pageNodes= self.pageNodes)

                    if toPath:
                        # print("[DEBUG]", fromPath, toPath)
                        # 目标页面中存在授权函数
                        # 且应为生命周期类自动触发的授权函数
                        for ann in self.taintedNodes:
                            if ann["authorizeTainted"] and ann["path"] == toPath and ann["callName"] in ["onLoad", "onLaunch", "onShow", "onReady"]:
                                annSourceTaintedAPI = extendUtil.getNodeByCallId(id=ann["authorizeTaintedBy"][0], nodes=self.taintedNodes)

                                # print("[DEBUG]", tnn["path"], toPath, annSourceTaintedAPI)
                                # print("DEBUG11]", tnn["branch"])
                                # tnn支配ann
                                # 满足：tnn的执行序列不包括异步函数 && ann的执行序列不包括异步函数
                                # &&（tnn的执行序列上无条件 &&｜ann的执行不影响tnn的条件） &&（ann的执行无条件｜ann无失败回调 | ann的执行不影响ann的条件）
                                if not extendUtil.existAsyncFunction(
                                    invokeAPINode = tnn, 
                                    nodes = self.funcNodes, 
                                    edges=self.funcEdges, 
                                    qnodes = self.queryResult["queryFunctionAndMethod"]) \
                                and not extendUtil.existAsyncFunction(
                                    invokeAPINode = ann, 
                                    nodes = self.funcNodes, 
                                    edges=self.funcEdges, 
                                    qnodes = self.queryResult["queryFunctionAndMethod"]) \
                                and (
                                    not tnn["branch"] or \
                                    not extendUtil.getAPIInvokeInfluenceBranch(invokeAPINode=ann, branchList=tnn["branch"], nodeList=self.queryResult["queryAuthorizeAPI"])
                                ) and \
                                    (
                                    not ann["branch"] or \
                                    annSourceTaintedAPI["failCallback"] == "NO_FAIL_CALLBACK" or \
                                    not extendUtil.isFailCallbackUpdateBranch(failCallback=annSourceTaintedAPI["failCallback"], branches=ann["branch"])
                                ):
                                    self.noConditionJumpRoute.append({
                                        "from": tnn["path"],
                                        "to": toPath,
                                        "branchInEncapsulation": annSourceTaintedAPI["branch"],
                                        "popupList":[{
                                            "path": ann["path"],
                                            "methodName": ann["callName"],
                                            "callName": annSourceTaintedAPI["callName"],
                                            "callLoc": annSourceTaintedAPI["callLoc"],
                                            "callId": annSourceTaintedAPI["callId"]
                                        }],
                                        "routeLoc": tn["callLoc"]
                                    })

                         
        # print("No condition jump:", self.noConditionJumpRoute)
        outputInfo = "---No condition jump---\n"
        for ncjrId, ncjr in enumerate(self.noConditionJumpRoute):
            outputInfo += "[%s] %s\n" % (ncjrId, ncjr)
        open(os.path.join(self.outputPath, "debug-%s.txt" % self.appID), "a").write(outputInfo)

        for ncjr in self.noConditionJumpRoute:
            triggerNCJR = copy.deepcopy(ncjr)
            # triggerNCJR["callName"] = tn["callName"]
            # triggerNCJR["event"] = tn["event"]
            loopRisk = {
                "riskId": len(self.risks),
                "riskType": "PopUp Loop - Caused By No Condition Jump",
                "riskInfo": triggerNCJR
            }

            self.risks.append(loopRisk)
            self.riskCount["loop"] += 1

    def getCrossPageSingleChoiceJumpLoop(self):
        # 单一选项页面跳转
        self.singleChoiceJumpRoute = []

        for alert in self.queryResult["queryAlertAPI"]:
            # alert的执行不应该有条件
            alertExistBranch = False
            for binfo in self.queryResult["queryBranchAndCondition"]:
                if alert["callId"] == binfo["callId"]:
                    alertExistBranch = True

            for tn in self.taintedNodes:
                # 存在跳转事件的函数节点
                # 有成功选项，没有失败选项
                if tn["routeInitTainted"] and alert["successCallId"] == tn["callId"] and \
                    not alert["successCallback"] == "NO_SUCCESS_CALLBACK" and alert["failCallback"] == "NO_FAIL_CALLBACK" and \
                    not alertExistBranch:
                    # print("[DEBUG]", alert)
                    # 找到路由流图中的起始
                    for pe in self.pageEdges:
                        if pe["callId"] == tn["callId"]:
                            self.singleChoiceJumpRoute.append({
                                "from": extendUtil.getPagePathByNodeId(id = pe["from"], pageNodes= self.pageNodes),
                                "to": extendUtil.getPagePathByNodeId(id = pe["to"], pageNodes= self.pageNodes),
                                "alertLoc": alert["callLoc"],
                                "routeLoc": tn["callLoc"]
                            })

        # print("Single choice jump:", self.singleChoiceJumpRoute)
        outputInfo = "---Single choice jump---\n"
        for scjrId, scjr in enumerate(self.singleChoiceJumpRoute):
            outputInfo += "[%s] %s\n" % (scjrId, scjr)
        open(os.path.join(self.outputPath, "debug-%s.txt" % self.appID), "a").write(outputInfo)

        for tn in self.taintedNodes:
            if tn["authorizeTainted"]:
                for scjr in self.singleChoiceJumpRoute:
                    # 粗略分析：省略了事件触发可能引起条件分支的变化
                    if scjr["to"] == tn["path"] and (tn["event"] or tn["callName"] in ["onLoad", "onLaunch", "onShow", "onReady"]):
                        taintedByList = extendUtil.getNodeInfosByCallIdList(nodeIdList=tn["authorizeTaintedBy"], nodes=self.taintedNodes)

                        triggerSCJR = copy.deepcopy(scjr)
                        triggerSCJR["event"] = tn["event"]
                        triggerSCJR["branchInEncapsulation"] = tn["branch"],
                        triggerSCJR["popupList"] = taintedByList

                        loopRisk = {
                            "riskId": len(self.risks),
                            "riskType": "PopUp Loop - Caused By Single Choice Alert",
                            "riskInfo": triggerSCJR
                        }

                        self.risks.append(loopRisk)
                        self.riskCount["loop"] += 1

    def queryPopUpLoop(self):
        # 由页面内、函数递归引起的循环弹窗
        self.getInPageFunctionReverseLoop()

        # 由页面间、无条件跳转引起的循环弹窗
        self.getCrossPageNoConditionJumpLoop()

        # 由页面间、提示单一选项引起的循环弹窗
        self.getCrossPageSingleChoiceJumpLoop()

    # ***** 弹窗打扰分析 *****

    def queryPopUpBother(self):
        # 查询弹窗打扰
        # for tn in self.taintedNodes:
        #     if tn["path"] == "app.js":
        #         print("->", tn)

        for tn in self.taintedNodes:
            if tn["authorizeTainted"]:
                # print("->", tn["authorizeTaintedBy"])
                taintedByList = extendUtil.getNodeInfosByCallIdList(nodeIdList=tn["authorizeTaintedBy"], nodes=self.taintedNodes)

                branches = []
                branchVariables = []
                failCallback = ""
                for tln in taintedByList:
                    for b in tln["branch"]:
                        branches.append(b)
                        branchVariables.append(b["branchVariable"])
                        if not tln["failCallback"] == "":
                            failCallback = tln["failCallback"]
                
                # 触发后无失败回调
                if failCallback == "NO_FAIL_CALLBACK":
                    botherRisk = {
                        "riskId": len(self.risks),
                        "riskType": "PopUp Bother - No Fail Callback",
                        "riskInfo": {   
                            "path": tn["path"],
                            "callName": tn["callName"],
                            "branchInEncapsulation": tn["branch"],
                            "popUpList": taintedByList
                        }
                    }
                    self.risks.append(botherRisk)
                    self.riskCount["bother"] += 1

                # 触发前无条件判断
                elif not branches:
                    botherRisk = {
                        "riskId": len(self.risks),
                        "riskType": "PopUp Bother - No Condition Control",
                        "riskInfo": {   
                            "path": tn["path"],
                            "callName": tn["callName"],
                            "branchInEncapsulation": tn["branch"],
                            "popUpList": taintedByList
                        }
                    }
                    self.risks.append(botherRisk)
                    self.riskCount["bother"] += 1
                
                # 触发后无条件更新
                else:
                    missAssignedVariable = []
                    for v in branchVariables:
                        if not failCallback == "NO_FAIL_CALLBACK" and v not in failCallback:
                            missAssignedVariable.append(v)
                    
                    if missAssignedVariable:
                        botherRisk = {
                            "riskId": len(self.risks),
                            "riskType": "PopUp Bother - No Condition Update in Fail Callback",
                            "riskInfo": {   
                                "path": tn["path"],
                                "callName": tn["callName"],
                                "branchInEncapsulation": tn["branch"],
                                "popUpList": taintedByList,
                                "conditionVariableNotUpdate":missAssignedVariable
                            }
                        }
                        self.risks.append(botherRisk)
                        self.riskCount["bother"] += 1

    # ***** 弹窗重复分析 *****
    def queryAuthEventCombineAPIRepeat(self):
        for ep in self.eventPopUpList:
            # 是否是成功回调才触发的弹窗
            authEventSuccessCallback = False
            if ep["eventAttribute"] == "onGetAuthorize":
                    authEventSuccessCallback = True
            # 
            if authEventSuccessCallback:
                print("[DEBUG]", ep)
                basicFlag = False
                extendFlag = False
                repeatPopUpList = []

                # 在成功回调里发现多个授权相同信息的API函数, 同一个函数内触发两个函数
                for p2 in ep["popUpList"]:
                    scopeNum, onlyAuthUser = extendUtil.getAuthUnofficialScopeNum(p2["callId"], self.queryResult)
                    if p2["callName"] == "my.getAuthCode" and scopeNum:
                        basicFlag = True
                        repeatPopUpList = extendUtil.addPopupInfoToList(value=p2, toList=repeatPopUpList)
                    if p2["callName"] == "my.getOpenUserInfo":
                        extendFlag = True
                        repeatPopUpList = extendUtil.addPopupInfoToList(value=p2, toList=repeatPopUpList)
                    if p2["callName"] == "my.getPhoneNumber" and not onlyAuthUser:
                        print(123, onlyAuthUser)
                        extendFlag = True
                        repeatPopUpList = extendUtil.addPopupInfoToList(value=p2, toList=repeatPopUpList)
                
                # 自动触发一个，事件函数内一个
                for plp in self.pageLaunchPopUpList:
                    if plp["path"] == ep["path"]:
                        for p3 in plp["popUpList"]:
                            scopeNum, onlyAuthUser = extendUtil.getAuthUnofficialScopeNum(p3["callId"], self.queryResult)
                            if p3["callName"] == "my.getAuthCode" and scopeNum:
                                basicFlag = True
                                repeatPopUpList = extendUtil.addPopupInfoToList(value=p3, toList=repeatPopUpList)
                            if p3["callName"] == "my.getOpenUserInfo":
                                extendFlag = True
                                repeatPopUpList = extendUtil.addPopupInfoToList(value=p3, toList=repeatPopUpList)
                            if p2["callName"] == "my.getPhoneNumber" and not onlyAuthUser:
                                extendFlag = True
                                repeatPopUpList = extendUtil.addPopupInfoToList(value=p3, toList=repeatPopUpList)
                
                # 二者均为事件触发
                # 在同页面找到了第二个授权相同信息API函数的调用
                for plp in self.eventPopUpList:
                    print("[DEBUG2]", plp)
                    if plp["path"] == ep["path"]:
                        for p4 in plp["popUpList"]:
                            # print("[DEBUG2]", p4, extendUtil.getAuthUnofficialScopeNum(p4["callId"], self.queryResult))
                            scopeNum, onlyAuthUser = extendUtil.getAuthUnofficialScopeNum(p4["callId"], self.queryResult)
                            if p4["callName"] == "my.getAuthCode" and scopeNum:
                                basicFlag = True
                                repeatPopUpList = extendUtil.addPopupInfoToList(value=p4, toList=repeatPopUpList)
                            if p4["callName"] == "my.getOpenUserInfo":
                                extendFlag = True
                                repeatPopUpList = extendUtil.addPopupInfoToList(value=p4, toList=repeatPopUpList)
                            if p4["callName"] == "my.getPhoneNumber" and not onlyAuthUser:
                                extendFlag = True
                                repeatPopUpList = extendUtil.addPopupInfoToList(value=p4, toList=repeatPopUpList)

                # print(basicFlag, extendFlag)
                if basicFlag and extendFlag:
                    triggerAECAR = {
                        "path": ep["path"],
                        "eventName": ep["callName"],
                        "branchInEncapsulation": ep["branchInEncapsulation"],
                        "popupList": repeatPopUpList                      
                    }

                    repeatRisk = {
                        "riskId": len(self.risks),
                        "riskType": "PopUp Repeat -- Event Combines with API",
                        "riskInfo": triggerAECAR
                    }
                    self.risks.append(repeatRisk)
                    self.riskCount["repeat"] += 1


    def queryPopUpRepeat(self):
        # 组件授权与API调用重复
        self.queryAuthEventCombineAPIRepeat()


    # ***** 输出结果 *****

    def outputRisk(self):
        savePath = os.path.join(self.outputPath, "risk-%s.json"%self.appID)
        print("Save risk result to %s" % savePath)
        json.dump([], open(savePath, "w", encoding="utf-8"), ensure_ascii=False)

        for r in self.risks:
            r["possible"] = False
            if "riskInfo" in r and "branchInEncapsulation" in r["riskInfo"] and r["riskInfo"]["branchInEncapsulation"]:
                r["possible"] = True
            
        json.dump(self.risks, open(savePath, "w", encoding="utf-8"), ensure_ascii=False)


# if __name__ == "__main__":
#     app = App(
#         dist="...",
#         db="...")
#     app.generateDB()
#     app.runQuery()
#     app.queryPopUpRisk()
#     app.outputRisk()
