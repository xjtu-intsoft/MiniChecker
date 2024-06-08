var ast = require('../../common/lib/ast.js'),
    sets = require('../../common/lib/sets.js'),
    cfg = require('../lib/cfg'),
    dominators = require('../lib/dominators'),
    esprima = require("esprima"),
    fs = require("fs"),
    path = require("path"),
    escodegen = require("escodegen"),
    estraverse = require("estraverse");

function iterCFG(nd, f) {
  function rec(nd) {
    iterCFG(nd, f);
  }
  
  if(!nd)
    return;
  
  switch(nd.type) {
  case 'Program':
    f(nd);
    f(ast.getAttribute(nd, 'fakeRoot'));
    nd.body.forEach(rec);
    break;
    
  case 'FunctionExpression':
    f(nd);
    f(ast.getAttribute(nd, 'fakeRoot'));
    rec(nd.body);
    break;
    
  case 'EmptyStatement':
  case 'DebuggerStatement':
  case 'VariableDeclaration':
  case 'ReturnStatement':
  case 'BreakStatement':
  case 'ThrowStatement':
    f(nd);
    break;
    
  case 'ExpressionStatement':
    f(nd);
    switch(nd.expression.type) {
    case 'CallExpression':
      f(nd.expression.callee);
      break;
    case 'AssignmentExpression':
      if(nd.expression.right.type === 'FunctionExpression')
        rec(nd.expression.right);
      break;
    default:
      throw new Error("unexpected expression statement");
    }
    break;

  case 'IfStatement':
    f(nd);
    rec(nd.consequent);
    rec(nd.alternate);
    break;
    
  case 'WhileStatement':
  case 'ForInStatement':
    f(nd);
    rec(nd.body);
    break;
    
  case 'LabeledStatement':
    f(nd);
    rec(nd.body);
    break;
    
  case 'TryStatement':
    f(nd);
    rec(nd.block);
    if(nd.handlers && nd.handlers[0])
      rec(nd.handlers[0].body);
    if(nd.finalizer)
      rec(nd.finalizer);
    break;
    
  case 'BlockStatement':
    for(var i=0;i<nd.body.length;++i)
      rec(nd.body[i]);
    break;
    
  default:
    break
    // throw new Error("unexpected statement of type " + nd.type);
  }
}


function dumpNode(nd) {
    if(!nd)
      return "<null>";
    var pos = ast.getPosition(nd);
    return nd.type + " at " + pos.start_line + ":" + pos.start_offset + "to" +  pos.end_line + ":" + pos.end_offset;
}

function dumpCFG(root) {
  var res = "";
  iterCFG(root, function(nd) {
    var succs = ast.getAttribute(nd, 'succ');
        idom = ast.getAttribute(nd, 'idom'),
        ipdom = ast.getAttribute(nd, 'ipdom');
    if(sets.size(succs) === 0) {
      res += dumpNode(nd) + " --> []\n";
    } else {
      res += dumpNode(nd) + " --> [" + sets.map(succs, dumpNode).join(', ') + "]\n";
    }
    res += "    immediate dominator: " + (idom ? dumpNode(idom) : "none") + "\n";
    res += "    immediate postdominator: " + (ipdom ? dumpNode(ipdom) : "none") + "\n";
  });
  return res;
}

function convertWALAToFormalFormat(walaOutput, fileAST){
    
}

function recursive(root, fileList){
    const arr = fs.readdirSync(root)
    
    arr.forEach(item => {
        const itemPath = path.join(root, item)
        const isDir = fs.statSync(itemPath).isDirectory()
        if(isDir) {
            const temp = itemPath + "/"
            recursive(temp, fileList)
        }
        else if (itemPath.endsWith(".js")) {
            console.log(itemPath)
            const fileContent = fs.readFileSync(itemPath).toString("utf-8");

            var sucFlag = false
            try {
                var ast = esprima.parseScript(fileContent, { loc: true, range: true });
                sucFlag = true
            }
            catch(e) {
                try {
                    var ast = esprima.parseModule(fileContent, { loc: true, range: true });
                    sucFlag = true
                }
                catch(e){
                    var ast = {}
                    console.log("AST generate fail.")
                }
            }

            cfg.buildCFG(ast);
            dominators.buildDominatorTrees(ast, true);
            var actual = dumpCFG(ast, fileContent);
            console.log(actual)
            if(sucFlag) { console.log("SUCCESS") };
        }
    })
}

let fList = []
recursive("...", fList)

// 
// 
// 
// 
// if(actual !== facts) {
//   console.log("actual:\n" + actual);
//   console.log("expected:\n" + facts); 
// }
// test.equal(actual, facts);
// test.done();
