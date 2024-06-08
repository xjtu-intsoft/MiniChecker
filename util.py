import re
import os
import copy
import tqdm
import numpy as np

authorizeCategoryDict = {
    "auth": ["my.getAuthCode", "my.ap.getAuthCode"],
    "location": ["my.openLocation", "my.openCarService", "my.getLocation", "my.ap.__openLifePayment", "my.startContinuousLocation", "my.ap.getMainSelectedCity"],
    "camera": ["my.scan", "cameraContext.takePhoto", "cameraFrameListener.start"],
    "album": ["my.chooseImage", "my.chooseVideo", "my.saveImage", "my.saveVideoToPhotosAlbum"],
    "recorder": ["RecorderManager.start", "my.startRecord", "my.stopRecord", "RecorderManager.stop", "my.cancelRecord"],
    "bluetooth":["my.connectBLEDevice", "my.openBluetoothAdapter", "my.getBeacons"],
    "contact": ["my.choosePhoneContact", "my.chooseAlipayContact", "my.chooseContact"],
    "clipboard": ["my.getClipboard"],
    "carrier": ["my.getCarrierName"],
    "openinfo":["my.getOpenUserInfo"],
    "phonenumber":["my.getPhoneNumber"]
}

# official provided key: "auth_base", "auth_user"
# self define key: "mobile", "user_name", "avatar", "cert_type", "cert_no", "person_birthday", "person_cert_expiry_date", "count", "Adress"
scopeKeyList = [
    "auth_base"
]
notRelatedKeyList = [
    "order_service"
]

asyncFuncList = [
    "my.confirm",
    "post",
    "tokenAPI"
]

def getTransferFromVariableDeclaration(vd):
    if vd:
        p = '([^=]*) = ([^=]*)'
        return re.match(p, vd).groups(0)
    else:
        return ("", "")

# print(getInitializerFromVariableDeclaration("money = parseFloat(res.data.data.elec_cost / 100) + parseFloat(res.data.data.serve_cost / 100)"))

def getRelativePath(path1, path2):
    # print(path1, path2)
    if "./" not in path2:
        if "'" in path2:
            path2 = path2.replace("'","")
        if '"' in path2:
            path2 = path2.replace('"',"")
        if path2[0] == "/":
            path2 = path2[1:]
        return path2 if ".js" in path2 else path2 + ".js"

    path2 = path2.replace("'","").replace("\\","").replace('"',"")
    # print(path2)
    if "./" in path2 and "../" not in path2:
        path2 = path2.replace("./","../")
    if "../" not in os.path.join(path1, path2):
        return os.path.join(path1, path2)
    elif os.path.basename(path1) == path1 and ".." in path2:
        return path2.replace("../", "")
    else:
        return os.path.relpath(os.path.join(path1, "../" + path2))

def findCallIdByPathAndName(nodes, path, name):
    Id = []
    for n in nodes:
        if n["path"] == path and n["callName"] == name:
                Id.append(n["callId"])
    return Id

def findNodeIdByPath(nodes, path):
    Id = []
    for n in nodes:
        if n["path"] == path:
            Id.append(n["nodeId"])
    return Id

def findModuleFunctionName(importName, exportReferences):
    for er in exportReferences:
        if er["export"] in ["default", "specifier", "moduleExportShortProperty"]:
            if importName == er["function"]:
                return er["function"]
        elif er["export"] == "moduleExportProperty":
            if importName == er["function"].split(":")[0]:
                return er["function"].split(":")[1]

def findDefineIdByPathAndName(funcNodes, funcPath, funcName):
    Id = []
    for fn in funcNodes:
        # print(funcName , funcPath, fn)
        # 由于pages中的函数引用与一般js文件中的引用方式不同
        # 如果是pages文件->Page对象中定义的函数一定要用this或者转移赋值后的this来调用
        if not "pages" in fn["path"] and fn["path"] == funcPath and fn["callType"] == "define" and fn["callName"] == str(funcName):
            Id.append(fn["callId"])
        elif "this" in str(funcName) and fn["callType"] == "define" and fn["path"] == funcPath and fn["callName"] == str(funcName).replace("this.",""):
            Id.append(fn["callId"])
    # if funcName == "this.initCity":
    #     print("[DEBUG]", Id)
    return Id

def findImortIdByName(importPath, funcNodes, funcName, impReference):
    # 先看节点所在文件有没有improt语句
    for ir in impReference:
        if ir["path"] == importPath:
            # 再看import的方法名
            importMethodName = ir["importMethod"]
            if importMethodName == funcName:
                # 最后去找有没有定义
                importMethodPath = getRelativePath(ir["path"],ir["importPath"])
                importFunctionInModuleId = findDefineIdByPathAndName(funcNodes=funcNodes, funcPath=importPath, funcName=ir["importMethod"])


def getNodeInfosByCallIdList(nodeIdList, nodes):
    infos = []
    for n in nodeIdList:
        node = getNodeByCallId(id = n , nodes = nodes)
        infos.append({
            "callId": node["callId"],
            "callName": node["callName"],
            "path": node["path"],
            "loc": node["callLoc"],
            "branch": node["branch"],
            "successCallback": node["successCallback"] if "successCallback" in node else "NO_SUCCESS_CALLBACK",
            "failCallback": node["failCallback"] if "failCallback" in node else "NO_FAIL_CALLBACK",
            "eventOpenType": node["eventOpenType"] if "eventOpenType" in node else "NO_OPEN_TYPE",
        })
    return infos

def getDifferentCallNumber(callList, callNodes):
    # 互相存在调用的删去
    # cParent <- cChild, 只视cParent为一个
    rmIndex = []
    for cParentIndex, cParent in enumerate(callList):
        cParentTaintedBy = getNodeByCallId(id = cParent["callId"], nodes = callNodes)["authorizeTaintedBy"]
        
        for cChildIndex, cChild in enumerate(callList):
            if not cParent["callId"] == cChild["callId"] and cChild["callId"] in cParentTaintedBy:
                rmIndex.append(cChildIndex)
    
    rmCallList = []
    for cParentIndex, cParent in enumerate(callList):
        if cParentIndex not in rmIndex:
            rmCallList.append(cParent)

    # print("DEBUG", rmCallList)
    
    dfCallMethod = []
    for c in rmCallList:
        # 同类API只计算一次
        cCategory = ""
        for cateKey in authorizeCategoryDict.keys():
            if c["callName"] in authorizeCategoryDict[cateKey]:
                cCategory = cateKey
            
        if cCategory and cCategory not in dfCallMethod:
            dfCallMethod.append(cCategory)
        
        # 组件引起的
        if not cCategory:
            if c["eventOpenType"] == "getAuthorize" and not "auth" in dfCallMethod and c["callName"] not in dfCallMethod:
                dfCallMethod.append(c["callName"])
    
    # print("DEBUG", dfCallMethod)
 
    return len(dfCallMethod)


def getDifferetCallNodeId(queryResult):
    dfCallNodeId = {}

    for cateKey in authorizeCategoryDict.keys():
        dfCallNodeId[cateKey] = []

    # init
    for aa in queryResult["queryAuthorizeAPI"]:
        for cateKey in authorizeCategoryDict.keys():
            if aa["callName"] in authorizeCategoryDict[cateKey] and aa["callName"] not in dfCallNodeId[cateKey]:
                dfCallNodeId[cateKey].append(aa["callId"])
    
    return dfCallNodeId


def getAuthorizeCategoryByCallName(callName):
    for cateKey in authorizeCategoryDict.keys():
        if callName in authorizeCategoryDict[cateKey]:
            return cateKey
    
    return "none"


def buildFunctionReference(queryResult, absolutePath, exceptFileList = []):
    funcReferences = queryResult["queryFunctionContainsCall"]
    thisReferences = queryResult["queryThisKeywordRelatedCall"]
    expReferences = queryResult["queryExport"]
    impReferences = queryResult["queryImport"]
    funcNodes = queryResult["queryFunctionAndMethod"]
    appReferences = queryResult["queryGetAppCallFunction"]

    funcEdges = []
    funcEdgeCounter = {"funcScope":0, "this":0, "this_true":0, "module":0, "getApp": 0}
  
    tqdmBar = tqdm.tqdm(total = len(funcReferences) + len(thisReferences) + len(impReferences) + len(appReferences))
    tqdmBar.set_description("* Function Call Graph Initialize:")
    for fr in funcReferences:
        tqdmBar.update(1)

        # 函数与其定义的函数存在依赖
        funcDefineId = findDefineIdByPathAndName(funcNodes=funcNodes, funcPath=fr["path"], funcName=fr["callName"])
        # if fr["callName"] == "onLoad":
        #     print("[DEBUG]", funcDefineId)

        for fdid in funcDefineId:
            funcEdges.append({
                "from":fdid,
                "to":fr["callId"],
                "edgeId": len(funcEdges)
            })
            funcEdgeCounter["funcScope"] += 1

        # 函数与其定义函数的调用存在依赖
        funcEdges.append({
            "from":fr["callId"],
            "to":fr["methodId"],
            "edgeId": len(funcEdges)
        })
        funcEdgeCounter["funcScope"] += 1

    tqdmBar.set_description("* This Keyword Reference")
    for tr in thisReferences:
        tqdmBar.update(1)
        # this关键词后面实际调用的函数名
        thisTrueCallName = tr["thisToCallName"].replace(tr["thisToVariable"]+".", "")
        # this关键词实际调用的函数Id
        thisTrueCallId = findCallIdByPathAndName(nodes=funcNodes, path=tr["path"], name=thisTrueCallName)
        # if thisTrueCallName == "getLocation":
        #     print("->", thisTrueCallId, tr["thisToCallId"])
        for i in thisTrueCallId:
            funcEdges.append({
                "from":i,
                "to":tr["thisToCallId"],
                "edgeId": len(funcEdges)
            })
            funcEdgeCounter["this_true"] += 1

        # this指代与上级函数间的调用
        funcEdges.append({
            "from": tr["thisToCallId"],
            "to": tr["methodId"],
            "edgeId": len(funcEdges)
        })
        funcEdgeCounter["this"] += 1
    
    tqdmBar.set_description("* Import and Export Reference")
    for ir in impReferences:
        tqdmBar.update(1)
        # 转换目录格式
        importPath = getRelativePath(ir["path"],ir["importPath"])
        # ES6特性：如果import语句引入了一个文件夹，则默认引入它目录下的index.js文件
        # 判断目录是文件夹还是文件
        importAbsolutePath = os.path.join(absolutePath, importPath)
        # print(importAbsolutePath)

        if os.path.isdir(importAbsolutePath):
            importPath = importPath + "/index.js"
        
        # print("[DEBUG]",ir["path"], importPath, ir["importMethod"])
        # 尝试寻找同名定义
        importFunctionInModuleIds = findDefineIdByPathAndName(funcNodes=funcNodes, funcPath=importPath, funcName=ir["importMethod"])
        # if ir["importMethod"] == "takeToken":
        #     print("--->",importFunctionInModuleIds, ir["path"])
        for importFunctionInModuleId in importFunctionInModuleIds:
            importFunctionCallIds = findCallIdByPathAndName(nodes=funcNodes, path=ir["path"], name=ir["importMethod"])
            for importFunctionCallId in importFunctionCallIds:
                # if ir["importMethod"] == "takeToken":
                #     print(ir, "--->", importFunctionCallId)
                # print(importPath, ir["importMethod"], importFunctionInModuleId, importFunctionCallId)
                funcEdges.append({
                    "from":importFunctionInModuleId,
                    "to":importFunctionCallId,
                    "edgeId": len(funcEdges)
                })

                funcEdgeCounter["module"] += 1
        # 没有找到同名定义，查看是否为export default，可对方法重命名型导入
        isExportDefault, exportDefindIds = getExportDefaultDefineId(exportReferences=expReferences, funcPath=importPath, funcNodes=funcNodes)
        # if ir["importMethod"] == "auth":
        #     print("--->",isExportDefault, exportDefindIds)
        if isExportDefault:
            renamedImportObject = ir["importMethod"]
            for exportDefindId in exportDefindIds:
                # 直接调用，export default k -> k();
                importFunctionCallIds = findCallIdByPathAndName(nodes=funcNodes, path=ir["path"], name=ir["importMethod"])
                if ir["importMethod"] == "auth" and ir["path"] == "app.js":
                    print("-->",importFunctionCallIds)
                for importFunctionCallId in importFunctionCallIds:
                    funcEdges.append({
                        "from":exportDefindId,
                        "to":importFunctionCallId,
                        "edgeId": len(funcEdges)
                    })

                    funcEdgeCounter["module"] += 1
                # 对象属性调用，export default {k} -> k.k();
                importPropertyFunctionCallIds = findCallIdByPathAndName(nodes=funcNodes, path=ir["path"], name=renamedImportObject + "." + ir["importMethod"])
                for importPropertyFunctionCallId in importPropertyFunctionCallIds:
                    funcEdges.append({
                        "from":exportDefindId,
                        "to":importPropertyFunctionCallId,
                        "edgeId": len(funcEdges)
                    })

                    funcEdgeCounter["module"] += 1

    tqdmBar.set_description("* Global Object Reference")
    for ar in appReferences:
        tqdmBar.update(1)
        appFunctionCallProperty = ar["callName"].replace("app.", "")
        # 寻找调用位置在app.js中的定义
        for possibleAppJsFile in ["app.js", "dist/app.js"]:
            appFunctionDefineIds = findDefineIdByPathAndName(funcNodes=funcNodes, funcPath=possibleAppJsFile, funcName=appFunctionCallProperty)
            for appFunctionDefineId in appFunctionDefineIds:
                funcEdges.append({
                    "from": appFunctionDefineId,
                    "to": ar["callId"],
                    "edgeId": len(funcEdges)
                })
                # print("[DEBUG]", appFunctionCallProperty, appFunctionDefineId, ar["callId"])

                funcEdgeCounter["getApp"] += 1

    tqdmBar.close()
    print("[SUCCESS] Build Function Reference Success. Count:", funcEdgeCounter)

    # for e in funcEdges:
    #     if e["from"] == 7761805245353790513:
    #         print(e)

    return funcEdges

def getExportDefaultDefineId(exportReferences, funcPath, funcNodes):
    for er in exportReferences:
        if er["path"] == funcPath and er["export"] == "default":
            return True, findDefineIdByPathAndName(funcNodes=funcNodes, funcPath=funcPath, funcName=er["function"])
    
    return False, []

def getEdgeById(id, edges):
    for e in edges:
        if e["edgeId"] == id:
            return e

def getNodeByCallId(id, nodes):
    for n in nodes:
        if n["callId"] == id:
            return n

def getNodesByCallId(id, nodes):
    ns = []
    for n in nodes:
        if n["callId"] == id:
            ns.append(n)
    return ns

def getNodeByNodeId(id, nodes):
    for n in nodes:
        if n["nodeId"] == id:
            return n

def getNodeByPath(path, nodes):
    res = []
    for n in nodes:
        if n["path"] == path:
            res.append(n)
    return res

def getEdgeById(id, edges):
    for e in edges:
        if e["edgeId"] == id:
            return e

def getPagePathByNodeId(id, pageNodes):
    for pn in pageNodes:
        if pn["nodeId"] == id:
            return pn["path"]

# # 补充函数调用的节点和边关联关系，用于搜索遍历
# def updateGraphRelationInfo(nodes, edges):
#     print("* Update graph relation info ...")

def taintSpread(nodes, edges, taintTypes):
    print("* Taint Spread ｜ ...")

    tqdmBar = tqdm.tqdm(total = len(nodes) + len(edges) + len(nodes) * len(taintTypes))
    tqdmBar.set_description("* Taint Spread ｜ Initialize:")

    # 初始化
    for n in nodes:
        tqdmBar.update(1)
        n["edgesFromThisNode"] = []
        n["edgesToThisNode"] = []

    for e in edges:
        tqdmBar.update(1)
        for n in nodes:
            if n["callId"] == e["from"]:
                n["edgesFromThisNode"].append(e["edgeId"]) 
            if n["callId"] == e["to"]:
                n["edgesToThisNode"].append(e["edgeId"])

    # 传播
   
    for tt in taintTypes:
        keyTainted = tt + "Tainted"
        keyTaintedBy = tt + "TaintedBy"
        keyTaintedRoot = tt + "TaintedRoot"

        tqdmBar.set_description("* Taint Spread ｜ Process %s:" % keyTainted)

        for n in nodes:
            tqdmBar.update(1)
            elapsedTime = tqdmBar.format_dict["elapsed"]
            rate = tqdmBar.format_dict["rate"]
            remainingTime = (tqdmBar.total - tqdmBar.n) / rate if rate and tqdmBar.total else 0

            # if remainingTime > 60 * 30:
            #     raise RuntimeError("Time Cost > 30 min.")


            if n[keyTainted]:
                # print("begin node at", n)
                waitForVisitEdgeIdList = n["edgesFromThisNode"]
                visitedNodeIdList = [n["callId"]]
                while(waitForVisitEdgeIdList):             
                    currentEdgeId = waitForVisitEdgeIdList.pop(0)
                    currentEdge = getEdgeById(edges = edges, id = currentEdgeId)
                    currentFromNode = getNodeByCallId(nodes = nodes, id = currentEdge["from"])
                    currentToNode = getNodeByCallId(nodes = nodes, id = currentEdge["to"])
                    if currentToNode:
                        # if currentEdge["from"] == -591752306498931175:
                        #     print("->",currentToNode, currentFromNode["branch"])

                        currentToNode[keyTainted] = True
                        for b in currentFromNode["branch"]:
                            if str(b) not in str(currentToNode["branch"]):
                                currentToNode["branch"].append(b)

                        for tb in currentFromNode[keyTaintedBy]:
                            if tb not in currentToNode[keyTaintedBy]:
                                currentToNode[keyTaintedBy].append(tb)      

                        if currentToNode["callId"] not in visitedNodeIdList:
                            visitedNodeIdList.append(currentToNode["callId"])
                            for e in currentToNode["edgesFromThisNode"]:
                                waitForVisitEdgeIdList.append(e)
                    else:
                        print("~ Warning: Error at finding node by id %s." % currentEdge["to"])
                
                # print("end node")
    print("* Taint Finished.")
    tqdmBar.close()

    return nodes


def taintSpreadByWarshall(nodes, edges, taintTypes):
    print("* Taint Spread by Warshall")

    # 生成邻接矩阵
    adjacentMatrix = np.zeros(shape=(len(nodes), len(nodes)))
    for nodeIndex, n in enumerate(nodes):
        n["nodeIndex"] = nodeIndex 

    tqdmBarA = tqdm.tqdm(total = len(edges))
    tqdmBarA.set_description("* Adjacent Matrix Generate")
    for e in edges:
        tqdmBarA.update(1)
 
        fromNode = getNodeByCallId(id=e["from"],nodes=nodes)
        toNode = getNodeByCallId(id=e["to"],nodes=nodes)
        if fromNode and toNode:
            adjacentMatrix[fromNode["nodeIndex"], toNode["nodeIndex"]] = 1
    tqdmBarA.close()
    
    print("[SUCCESS] Adjecent Matrix Generate Success.")
    print(adjacentMatrix.sum(), adjacentMatrix.shape)

    tqdmBarB = tqdm.tqdm(total = len(edges))
    tqdmBarB.set_description("* Warshell")

    # 临接矩阵运算
    tempMatrix = np.zeros(shape=(len(nodes), len(nodes)))
    for k in range(0, len(nodes)):
        tqdmBarB.update(1)

        for i in range(0, len(nodes)):
            for j in range(0, len(nodes)):
                tempMatrix[i][j] = adjacentMatrix[i][j] | (adjacentMatrix[i][k] & adjacentMatrix[k][j])
    
        adjacentMatrix = tempMatrix.copy()

    tqdmBarB.close()

    # 返回临接矩阵运算结果（未完成）


def formatNodesAndEdges(nodes, edges):
    # 绘图用
    new_nodes = []
    for idx, n in enumerate(nodes):
        new_nodes.append({
            "id": idx,
            "label": n["callId"],
            "name": n["callName"],
            "tainted": n["tainted"],
            "initTainted": n["initTainted"]
        })

    cur_node_length = len(new_nodes)
    new_edges = []
    for e in edges:
        sourceLongId = e["from"]
        targetLongId = e["to"]
        source = None
        target = None
        for n in new_nodes:
            if n["label"] == sourceLongId:
                source = n["id"]
            if n["label"] == targetLongId:
                target = n["id"]
        if not source:
            source = cur_node_length
            new_nodes.append({
                "id": cur_node_length,
                "label": sourceLongId,
                "name": "__NOTFIND__",
                "tainted": False,
                "initTainted": False
            })
            cur_node_length += 1
            

        if not target:
            target = cur_node_length
            new_nodes.append({
                "id": cur_node_length,
                "label": targetLongId,
                "name": "__NOTFIND__",
                "tainted": False,
                "initTainted": False
            })
            cur_node_length += 1

        new_edges.append({
            "source": source,
            "target": target
        })

    return new_nodes, new_edges

# XML事件和Js函数节点绑定
def getEventNode(nodes, events, eventRef):
    for n in nodes:
        n["event"] = None
    
    # 直接调用
    for n in nodes:
        for e in events:
            if e["path"] == n["path"].replace(".js", ".axml") and e["eventAttrValue"] == n["callName"]:
                n["event"] = e
            
    # 通过template引入的
    for n in nodes:
        for ref in eventRef:
            if ref["callName"] == n["callName"] and ref["pagePath"] == n["path"]:
                n["event"] = ref["sourceEvent"]
    
    return nodes


# 构建route graph
def buildPageReference(nodeInfo, edgeInfo):
    nodes = [{
        "path":"app.js",
        "nodeId": 0
    }]
    for n in nodeInfo:
        nodes.append({
            "path": n + ".js",
            "nodeId": len(nodes)
        })
    
    edges = []
    for n in nodes:
       for e in edgeInfo:
            if e["path"] == n["path"]:
                toPath, toParams = getPathFromUrlString(e["path"], e["routeTarget"])

                if not ".js" in toPath:
                    toPath = toPath + ".js"

                toPathNodeIds = findNodeIdByPath(nodes=nodes, path=toPath)
                
                # if n["nodeId"] == 1:
                    # print("[DEBUG]", toPathNodeIds, getPagePathByNodeId(toPathNodeIds[0], nodes))

                for tpid in toPathNodeIds:
                    edges.append({
                        "from": n["nodeId"],
                        "to": tpid,
                        "callId": e["callId"],
                        "params": toParams,
                        "event": e["pageMethodName"],
                        "edgeId": len(edges)
                    })

    # for e in edges:
    #     print("[DEBUGe]", e)
    return nodes, edges

# 从route URL中抽取路径和参数
def getPathFromUrlString(curPath, inputUrlStr):
    # print("[DEBUG]", curPath, inputUrlStr)
    if inputUrlStr == "undefine":
        return "", ""
    urlPath = inputUrlStr.split(":")[1].replace(" ","").replace("`","").replace("+","").replace("'","")
    if urlPath[0] == "/":
        urlPath = urlPath[1:]
    
    
    realPath = getRelativePath(path1=curPath, path2=urlPath)
    # print(curPath, urlPath, realPath)

    relativePath = realPath
    params = None
    if "?" in relativePath:
        relativePath = realPath.split("?")[0]
        paramsStr = realPath.split("?")[1]
        params = []
        if "&" in paramsStr:
            for p in paramsStr.split("&"):
                if "=" in p:
                    pName = p.split("=")[0]
                    pValue = p.split("=")[1]
                    params.append({
                        "name": pName,
                        "value": pValue
                    })

    return relativePath, params


def getPathByNodeId(id, nodes):
    for n in nodes:
        if n["nodeId"] == id:
            return n["path"]

# 路由函数与事件函数依赖绑定
def eventLocate(nodes, edges, elements):
    for e in edges:
        eventName = e["event"]
        e["element"] = findElementByName(name = eventName, elements = elements, path = getPathByNodeId(id = e["from"], nodes = nodes))
    
    return edges


def findElementByName(name, elements, path):
    for c in elements:
        if c["eventAttrValue"] == name and c["path"] == path.replace(".js", ".axml"):
            return c["elementId"]


def findPathFromRouteGraph(nodes, edges, start, end):
    # print("Try to find path from %s to %s..." % (start, end))
    res = []
    startNodes = findNodeIdByPath(nodes=nodes, path=start)
    # print("Start Node ID: %s" % startNodes)
    for snid in startNodes:
        for e in edges:
            if e["from"] == snid:
                DFSFindPath(nodes = nodes, 
                         edges = edges, 
                         endPath=end, 
                         curNodeId=snid, 
                         curEdgeId = e["edgeId"], 
                         curPath=[], 
                         resPath=res, 
                         visitedNode=[],
                         visitedEdge=[])
    
    formatRes = []
    for i, r in enumerate(res):
        # print("---Path: %s/%s---" % (i, len(res)))
        formatPath = []
        for j, n in enumerate(r):
            formatPagePath = getPathByNodeId(id = n["nodeId"], nodes = nodes)
            formatEdge = getEdgeById(id=n["edgeId"], edges=edges)
            # print("Node: %s/%s, Page: %s, Edge: %s" % (j, len(r), formatPagePath, formatEdge))
            formatPath.append({
                "curPathId": i + 1,
                "totalPaths": len(res),
                "curStepId": j + 1,
                "totalSteps": len(r),
                "curPath": formatPagePath,
                "curEvent": formatEdge["event"],
                "curElementId": formatEdge["element"]          
            })
        formatRes.append(copy.deepcopy(formatPath))

    return formatRes
           

def DFSFindPath(nodes, edges, endPath, curNodeId, curEdgeId, curPath, resPath, visitedNode, visitedEdge):
    # nodes, edges: 图信息
    # endPath: 目标路径
    # curNodeId, curEdgeId, curPath: 当前访问路径与节点信息
    # resPath: 要保留的信息，返回可达路径
    # visitedNode, visitedEdge: 访问过的节点和边，避免陷入死循环

    # print(curNodeId, curPath)
    for e in edges:
        if curNodeId == e["from"]:
            n = e["to"]
            nextNode = getNodeByNodeId(id = n, nodes=nodes)
            if nextNode["path"] == endPath:
                curPath.append({
                    "nodeId": n,
                    "edgeId": e["edgeId"]
                })
                existedPath = False
                for r in resPath:
                    if str(curPath) == str(r):
                        existedPath = True
                if not existedPath:
                    resPath.append(copy.deepcopy(curPath))
                curPath.pop()

            else:
                if n not in visitedNode and e["edgeId"] not in visitedEdge:
                    visitedNode.append(n)
                    visitedEdge.append(e["edgeId"])
                    curPath.append({
                        "nodeId": n,
                        "edgeId": e["edgeId"]
                    })
                    DFSFindPath(nodes, edges, endPath, n, e["edgeId"], curPath, resPath, visitedNode, visitedEdge)
                    curPath.pop()


# 更新节点的分支信息
def updateBranchInfo(queryResult):
    print("Update branch info...")
    nodes = queryResult["queryFunctionAndMethod"]
    branchInfos = queryResult["queryBranchAndCondition"]

    # 直接进行nodes * branchInfos对比耗时过长
    # 选择首先按callId进行分组，然后赋值给nodes
    branchInfoInNodes = {}
    for bi in branchInfos:
        if bi["callId"] not in branchInfoInNodes:
            branchInfoInNodes[bi["callId"]] = []

        branchInfoInNodes[bi["callId"]].append({
            "branchLoc": bi["branchLoc"],
            "branchCondition": bi["branchCondition"],
            "branchVariable": bi["branchVariable"]
        })

    for n in nodes:
        n["branch"] = []
        if n["callId"] in branchInfoInNodes:
            n["branch"] = branchInfoInNodes[n["callId"] ]

    # for n in nodes:
    #     n["branch"] = []

    # for n in nodes:
    #     for bi in branchInfos:
    #         if n["callId"] == bi["callId"]:
    #             n["branch"].append({
    #                 "branchLoc": bi["branchLoc"],
    #                 "branchCondition": bi["branchCondition"],
    #                 "branchVariable": bi["branchVariable"]
    #             })
    return nodes


def findLoopsfromFuncGraph(nodes, edges):
    print("* Find loop...")
    loopResult = []

    tqdmBar = tqdm.tqdm(total = len(nodes))
    tqdmBar.set_description("* Loop Search:")

    for n in nodes:
        tqdmBar.update(1)

        if n["callType"] == "define":
            nid = n["callId"]
            nloop = []
            DFSFindLoop(nodes=nodes,
                        edges=edges,
                        endNodeId=nid,
                        curNodeId=nid,
                        curPath=[],
                        resPath=nloop,
                        visitedNode=[],
                        visitedEdge=[])
            
            # 只保留NodeId
            formatLoop = []
            for l in nloop:
                newl = []
                for lnode in l:
                    loopNode = getNodeByCallId(id = lnode["nodeId"], nodes=nodes)
                    # 简化属性
                    newl.append({
                        "path": loopNode["path"],
                        "callName": loopNode["callName"],
                        "callLoc": loopNode["callLoc"],
                        "callId": loopNode["callId"],
                        "branch": loopNode["branch"],
                        "event": loopNode["event"]
                    })
                formatLoop.append(newl)
            
            if formatLoop:
                loopResult.append({
                    "path": n["path"],
                    "callId": nid,
                    "callName":n["callName"],
                    "callLoc": n["callLoc"],
                    "loop":formatLoop
                })
    
    print("* Loop Result: %d." % len(loopResult))
    tqdmBar.close()
    return loopResult


def DFSFindLoop(nodes, edges, endNodeId, curNodeId, curPath, resPath, visitedNode, visitedEdge):
   for e in edges:
        if curNodeId == e["from"]:
            n = e["to"]

            if n == endNodeId:
                curPath.append({
                    "nodeId": n,
                    "edgeId": e["edgeId"]
                })
                existedPath = False
                for r in resPath:
                    if str(curPath) == str(r):
                        existedPath = True
                if not existedPath:
                    resPath.append(copy.deepcopy(curPath))
                curPath.pop()

            else:
                if n not in visitedNode and e["edgeId"] not in visitedEdge:
                    visitedNode.append(n)
                    visitedEdge.append(e["edgeId"])
                    curPath.append({
                        "nodeId": n,
                        "edgeId": e["edgeId"]
                    })
                    DFSFindLoop(nodes, edges, endNodeId, n, curPath, resPath, visitedNode, visitedEdge)
                    curPath.pop()

def isFailCallbackUpdateBranch(failCallback, branches):
    update = False
    for b in branches:
        if b["branchVariable"] in failCallback:
            update = True
    
    return update

def isInSamePage(jsfilePath, xmlfilePath):
    if jsfilePath.replace(".js","") == xmlfilePath.replace(".axml", ""):
        return True
    return False


def getAuthUnofficialScopeNum(authAPICallID, queryResult):
    # 获取getAuthCode的scope中非官方字段的数量
    authAPIScope = []
    for authAPI in queryResult["queryAuthorizeAPI"]:
        if authAPI["callId"] == authAPICallID and not authAPI["scope"] == "NO_SCOPE":
            try:
                authAPIScopeText = re.sub("[\'\"(\)]", "", authAPI["scope"])
                authAPIScope = authAPIScopeText.split(",")
            except Exception as e:
                print("Auth Scope Text Process Error.")

            if authAPIScope:
                for officialScopeKey in scopeKeyList:
                    if officialScopeKey in authAPIScope:
                        authAPIScope.remove(officialScopeKey)
                
                for unofficialScopeKey in notRelatedKeyList:
                    if unofficialScopeKey in authAPIScope:
                        authAPIScope.remove(unofficialScopeKey)

    # 部分节点可能在传递过程中使用形参的方式传值
    # 这里采用粗略过滤的方式对节点再扫一遍
    if len(authAPIScope) == 0:
        for n in queryResult["queryFunctionAndMethod"]:
            if "scopes" in n["callName"] and "auth_user" in n["callName"] and "auth_user" not in authAPIScope:
                authAPIScope.append("auth_user")

    # 如果只有auth_user关键字，只会影响openuserinfo而不会影响getphonenumber
    onlyAuthUser = False
    if len(authAPIScope) == 0 or (len(authAPIScope) == 1 and "auth_user" in authAPIScope):
        onlyAuthUser = True
    # print(len(authAPIScope))
    return len(authAPIScope), onlyAuthUser

def getTemplateDefineFile(templateUse, queryResult):
    # 获取xml引用中template属性的定义来源文件
    for tmd in queryResult["queryXMLTemplate"]:
        if tmd["templateType"] == "define" and templateUse["templateName"] == tmd["templateName"]:
            for tmref in queryResult["queryXMLImport"]:
                # print(tmref["path"], getRelativePath(tmref["path"], tmref["referenceFile"]))
                if tmref["path"] == templateUse["path"]:
                    # 待解决：引用可能存在相对目录
                    return tmd["path"]
    
    return ""

def addPopupInfoToList(value, toList):
    # 向列表中添加信息
    if str(value) not in str(toList):
        toList.append(value)
    
    return toList

def getAPIInvokeInfluenceBranch(invokeAPINode, branchList, nodeList):
    # 判断API节点的执行是否会影响条件列表里面的变量
    influenceFlag = False
    for branch in branchList:
        for atb in invokeAPINode["authorizeTaintedBy"]:
            # print(getNodeByCallId(atb, nodeList))
            if branch["branchVariable"] in getNodeByCallId(atb, nodeList)["successCallback"]:
                influenceFlag = True
    
    return influenceFlag

def getPerformTraceNodes(endNode, nodes, edges):
    # 获得一个节点的执行路径上的所有节点
    performNode = [endNode]
    waitForCheckNode = [endNode]
    existCheckNodeIds = []
    while waitForCheckNode:
        checkNode = waitForCheckNode.pop()
        for e in checkNode["edgesToThisNode"]:
            enode = getEdgeById(id = e, edges = edges)
            fromNode = getNodeByCallId(id = enode["from"], nodes = nodes)

            if not fromNode["callId"] in existCheckNodeIds:
                existCheckNodeIds.append(fromNode["callId"])

                performNode.append(fromNode)
                waitForCheckNode.append(fromNode)

    return performNode
  
def existAsyncFunction(invokeAPINode, nodes, edges, qnodes):
    # 判断执行API的执行序列中是否有异步函数

    deepNodes = getPerformTraceNodes(endNode=invokeAPINode, nodes = nodes, edges = edges)
    for dn in deepNodes:
        for asyncFunc in asyncFuncList:
            if asyncFunc in dn["callName"]:
                return True
    
    for qnode in qnodes:
        for asyncFunc in asyncFuncList:
            if invokeAPINode["callId"] == qnode and asyncFunc in invokeAPINode["methodName"]:
                return True

    # print("---")     
    # print(invokeAPINode)
    # for n in deepNodes:
    #     print(n["callName"])
            
    return False
