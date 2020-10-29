---
draft: true
---
# LLVM 入门教程之 frontend 介绍

## 前言



## clang



icc(Intel C++ Compiler)





- 实现词法分析器 
- 定义抽象语法树 
- 实现语法分析器 
-  解析简单表达式 
-  解析二元表达式 
- 为解析编写驱动 

### 定义抽象语法树 

AST 的使用集中在语义分析阶段，在这个阶段，编译器会检查程序和语言元素是否正 确使用。

http://clang.llvm.org/docs/IntroductionToTheClangAST.html



### 实现语法分析器 



语法分析器（parser）根据语言的语法规则来解析代码，解析阶段决定了输入的代码是 否能够根据既定的语法组成token流 5。在此阶段会构造出一棵解析树，而语法分析器则会 定义一些函数来把代码组织成一种被称为AST的数据结构



### 解析简单的表达式 





### 生成 LLVM IR

实现 codegen 函数，

这一函数返回值是 LLVM Value 对象，它表示了静态单赋值（SSA）对象。在 Codegen 过程中还需要定义几个静态对象。 



Module_Ob模块包含了代码中的所有函数和变量。 

Builder对象帮助生成 LLVM IR 并且记录程序的当前点，以插入 LLVM 指令。另外， Builder对象有创建新指令的函数。 

Named_Values map 对象记录当前作用域中的所有已定义值，充当符号表的功能。 





### codegen

Codegen()函数使用了LLVM内建的函数调用来生成IR

