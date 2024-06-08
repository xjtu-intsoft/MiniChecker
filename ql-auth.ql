/**
 * @name Call graph
 * @description An edge in the call graph.
 * @kind problem
 * @problem.severity recommendation
 * @id js/meta/alerts/call-graph
 * @tags meta
 * @precision very-high
 */

import javascript

from InvokeExpr invokeexpr, Function f
where
    invokeexpr.getEnclosingFunction() = f and
    (
        invokeexpr.getCallee().toString() = "my.openLocation" or
        invokeexpr.getCallee().toString() = "my.openCarService" or
        invokeexpr.getCallee().toString() = "my.getLocation" or
        invokeexpr.getCallee().toString() = "my.ap.__openLifePayment" or
        invokeexpr.getCallee().toString() = "my.startContinuousLocation" or
        invokeexpr.getCallee().toString() = "my.ap.getMainSelectedCity" or
        invokeexpr.getCallee().toString() = "my.scan" or
        invokeexpr.getCallee().toString() = "cameraContext.takePhoto" or
        invokeexpr.getCallee().toString() = "cameraFrameListener.start" or
        invokeexpr.getCallee().toString() = "my.chooseImage" or
        invokeexpr.getCallee().toString() = "my.chooseVideo" or
        invokeexpr.getCallee().toString() = "my.saveImage" or
        invokeexpr.getCallee().toString() = "my.saveVideoToPhotosAlbum" or
        invokeexpr.getCallee().toString() = "RecorderManager.start" or
        invokeexpr.getCallee().toString() = "my.startRecord" or
        invokeexpr.getCallee().toString() = "my.stopRecord" or
        invokeexpr.getCallee().toString() = "RecorderManager.stop" or
        invokeexpr.getCallee().toString() = "my.cancelRecord" or
        invokeexpr.getCallee().toString() = "my.connectBLEDevice" or 
        invokeexpr.getCallee().toString() = "my.openBluetoothAdapter" or
        invokeexpr.getCallee().toString() = "my.getBeacons" or
        invokeexpr.getCallee().toString() = "my.choosePhoneContact" or     
        invokeexpr.getCallee().toString() = "my.chooseAlipayContact" or
        invokeexpr.getCallee().toString() = "my.chooseContact" or
        invokeexpr.getCallee().toString() = "my.getClipboard" or   
        invokeexpr.getCallee().toString() = "my.getCarrierName" or
        invokeexpr.getCallee().toString() = "my.getAuthCode" or
        invokeexpr.getCallee().toString() = "my.ap.getAuthCode" or
        invokeexpr.getCallee().toString() = "my.getOpenUserInfo" or
        invokeexpr.getCallee().toString() = "my.getPhoneNumber" 
    )

select invokeexpr, "API: [" + invokeexpr.getCallee().toString() + "]" + " is called in [" + f.describe() + "]" + " at [" + f.getLocation() + "]."
