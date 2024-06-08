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

from DataFlow::Node invoke, Function fdef, Function fcall
where invoke.(DataFlow::InvokeNode).getACallee() = fcall and invoke.(DataFlow::InvokeNode).getEnclosingFunction() = fdef
select invoke, "Called: [" + fcall.describe() + "][" + fcall.getLocation()+ "]" + " Define in: [" + fdef.describe()  + "][" + fdef.getLocation()+ "]."
