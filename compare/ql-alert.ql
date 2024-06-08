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
    invokeexpr.getEnclosingFunction() = f and invokeexpr.getCallee().toString() = "my.alert"

select invokeexpr, "API: [" + invokeexpr.getCallee().toString() + "]" + " is called in [" + f.describe() + "]" + " at [" + f.getLocation() + "]."
