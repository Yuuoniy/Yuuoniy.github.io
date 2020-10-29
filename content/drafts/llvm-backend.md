---
draft: true
---
# LLVM  Backend

# 前言

LLVM backend的主要功能是code gen，也就是代码生成，其中包括若干个code gen分析换转化pass将LLVM IR转换成特定目标架构的机器 代码。

# overview

在得到优化过的 LLVM IR 之后，下一个阶段就是把它转为目标平台的指令了。LLVM 通过 SelectionDAG 来将 IR 转为机器指令。在此过程中，指令通过 DAG 的节点来表示，最 后线性的 IR 便被转为了 SelectionDAG。在此之后，SelectionDAG 还要经历以下几个阶段。 

- 由 LLVM IR 创建 SelectionDAG。 

-  SelectionDAG 节点合法化。 

-  DAG 合并优化。

-  针对目标指令的指令选择。

-  调度并发射机器指令。 

- 寄存器分配——SSA 解构、寄存器赋值、寄存器溢出。 

- 发射机器码。 

  所有以上步骤在 LLVM 中都是模块化的。 



LLVM 的后端有一套流水线架构，指令经历了许多阶段：从 LLVM IR 到 SelectionDAG、MachineDAG、MachineInstr，最终到MCInst

指令选择-指令调度-寄存器分配





- 指令选择阶段

  将 IR 转化为指定目标的 SelectionDAG 结点。将三地址结构的IR转化为有向无环图(DAG) 、

### 指令选择



### 指令调度

机器执行线性指令集，而现在我们得到的机器指令仍是 DAG 形式的，所以还需要把 DAG 转为线性指令集，这个过程可以通过对 DAG 进行一次拓扑排序完成。但还需要优化。



### 寄存器 分配

LLVM 采用了贪心法来进行寄存器分配，即活动周期越长的变量先分配寄存器。生存 周期短的变量则填补可用寄存器的时间间隙，减少溢出权重。

tableGen



### 代码发射



LLVM中 代码发射有两种方式，一种是JIT，直接把代码发射到内存，然后执行；另一种则是使用 MC框架，对所有的后端目标平台来说，都可以发射到汇编和目标文件。

### tablegen

ablegen将.td文件转为.inc 文件，可以在.cpp文件中用#include语法来引入，从而引用其中的寄存器。

### 定义指令集



### 参考链接




1. [Writing an LLVM Backend](https://llvm.org/docs/WritingAnLLVMBackend.html) 
2. [Building an LLVM Backend](https://llvm.org/devmtg/2014-04/PDFs/Talks/Building an LLVM backend.pdf) 
3. 