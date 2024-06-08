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

from InvokeExpr invokeexpr, Function f, string arg
where
    invokeexpr.getEnclosingFunction() = f and arg = invokeexpr.getAnArgument().toString() and
    (
        invokeexpr.getCallee().toString() = "my.switchTab" or
        invokeexpr.getCallee().toString() = "my.navigateTo" or
        invokeexpr.getCallee().toString() = "my.navigateBack" or
        invokeexpr.getCallee().toString() = "my.redirectTo" or 
        invokeexpr.getCallee().toString() = "my.reLaunch" or
        invokeexpr.getCallee().toString() = "my.navigateToMiniProgram" or
        invokeexpr.getCallee().toString() = "my.navigateBackMiniProgram" or
        invokeexpr.getCallee().toString() = "my.openAlipayApp" or
        invokeexpr.getCallee().toString() = "my.ap.navigateToAlipayPage" or
        invokeexpr.getCallee().toString() = "my.ap.openURL"
    )

select invokeexpr, "API: [" + invokeexpr.getCallee().toString() + "]" + " is called in [" + f.describe() + "]" + " at [" + f.getLocation() + "]. Its args: [" + arg + "]."
