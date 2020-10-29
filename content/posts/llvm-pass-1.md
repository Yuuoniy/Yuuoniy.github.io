---
title: "LLVM 入门教程之 Pass 编写"
date: 2020-07-11T09:39:11+08:00
draft: false
---



## 前言

本篇文章作为 Pass 编写的入门，主要介绍以下内容:

- 示例 Pass 编写
- Pass 编译构建和运行
- Pass 不同子类
- Pass 注册
- Pass 间依赖

## 示例

首先我们先结合一个小示例，尝试编写 Pass，之后再详细介绍涉及的内容。

```c++
#include "llvm/Pass.h" //添加头文件
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
using namespace llvm;  //添加 llvm 命名空间
 
namespace {   // 定义匿名命名空间 
  struct SkeletonPass : public FunctionPass { // 定义 SkeletonPass 继承 FunctionPass
    static char ID;  // // ID 标识
    SkeletonPass() : FunctionPass(ID) {}  

    virtual bool runOnFunction(Function &F) { //// 重载 runOnFunction 函数，接受Function类型参数
      errs() << "I saw a function called " << F.getName() << "!\n";  // 输出函数名
      return false; // 没有修改 F，因此返回 false
    }
  };
}

char SkeletonPass::ID = 0; //id ，随便指定一个数字就可以

// Register the pass so `opt -skeleton` runs it.
static RegisterPass<SkeletonPass> X("skeleton", "a useless pass"); //注册Pass
```

errs() 为LLVM 中 C++ 的输出流。

以上的示例 Pass 会在每个函数运行时输出函数名。

## 构建

编写好 Pass 后，需要进行编译构建，有两种构建方式：

1. 将 Pass 放至 LLVM 源码目录，并修改已有的 CMakeLists 文件。可以直接查看 [官方示例](https://llvm.org/docs/WritingAnLLVMPass.html#setting-up-the-build-environment) 
2. 单独建立目录，并编写好 CMakeLists文件。

单独构建目录结构大致如下：

```
pass-project
   - CMakeLists.txt
   - MyPass
      - mypass.cpp
   	  - CMakeLists.txt
   - build
```

参考 [llvm-pass-skeleton](https://github.com/sampsyo/llvm-pass-skeleton) (该repo有不同的分支，用于展示不同的用法），不过由于 llvm-pass-skeleton 依赖的版本比较旧，对应的编译选项 C++11 已经不适合，因此需要修改下 CMakeLists 文件，在这里提供我使用的：

 `llvm-pass-skeleton` 下的 CMakeList.txt (添加编译选项标准为 C++14): 

```cmake
cmake_minimum_required(VERSION 3.1)
project(Skeleton)

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_compile_options(-std=c++14) 
add_subdirectory(skeleton)  # Use your pass name here.
```

skeleton 内的 CMakeList.txt(删除了 `target_compile_features(SkeletonPass PRIVATE cxx_range_for cxx_auto_type` 因为该语句使用C++11来编译Pass)

```cmake
add_library(SkeletonPass MODULE
    # List your source files here.
    Skeleton.cpp
)
# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(SkeletonPass PROPERTIES
    COMPILE_FLAGS "-fno-rtti"
)
# Get proper shared-library behavior (where symbols are not necessarily
# resolved when the shared library is linked) on OS X.
if(APPLE)
    set_target_properties(SkeletonPass PROPERTIES
        LINK_FLAGS "-undefined dynamic_lookup"
    )
endif(APPLE)
```

这里我使用的 Skeleton 文件是 noauto 分支下的。

在 build 目录依次执行 

```
cmake ..
make
```

编译成功：

```shell
# mm @ iZ2ze2gbki9vcb415a0z6rZ in ~/llvm-learn/llvm-pass-skeleton/build on git:master x [11:41:04] 
$ make
Scanning dependencies of target SkeletonPass
[ 50%] Building CXX object skeleton/CMakeFiles/SkeletonPass.dir/Skeleton.cpp.o
[100%] Linking CXX shared module libSkeletonPass.so
[100%] Built target SkeletonPass
```

在 `build/skeleton` 目录下可以看到 `libSkeletonPass.so` 文件。

## 使用 opt 运行 Pass

获得 so 文件后，我们通过 opt 的 -load 选项动态加载此文件，选择 pass 执行。

通过 opt -help 命令也可以看到我们的 pass:

```python
$ opt -load ./libSkeletonPass.so -help | grep skeleton
      --skeleton                                         - a useless pass
```

直接运行 `opt -load ./libSkeletonPass.so -skeleton test.ll -o test.ll` 就可对 test.ll 文件应用编写好的 Pass。

也可以使用C/C++ 编写文件，使用 clang 转化为 LLVM IR 再使用 opt 命令运行。



## 使用 Clang 自动化运行 Pass

每次使用 clang 编译获得LLVM IR，再通过 opt 运行 pass，再再使用 opt 执行一些优化，这个过程十分繁琐。

我们可以在Pass 文件将注册部分写成这样(MyPass 是自定义的Pass 类)， llvm-pass-skeleton的master 分支下就是这样编写的，可以对比一下 noauto 分支下的不同。

```c++
static void registerMyPass(const PassManagerBuilder &,
                           PassManagerBase &PM) {
    PM.add(new MyPass()); // PM 用于添加 Pass
}
static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                   registerMyPass); // 第一个参数表示加载的时间，枚举值，第二个参数是函数指针
```

之后便可以通过以下命令直接运行了

```shell
$ clang -Xclang -load -Xclang mypass.so ...
```

这里我简单地编写了一些 Demo 进行测试（Pass 就是SkeletonPass)

```c
#include <stdio.h>
void func2(){
        printf("hello world");
}
void func(){
        func2();
}
int main(){
        func();
        return 0;
}
```

执行结果如下：

```shell
$ clang -Xclang -load -Xclang ./libSkeletonPass.so test.c
I saw a function called func2!
I saw a function called func!
I saw a function called main!
```

## Pass

通过以上内容，可以大致了解 Pass 的编写，构建和运行，接下来我们进一步了解 Pass 的相关内容。

推荐先阅读这篇文章，[llvm学习（七）：IR 的基础结构](https://www.leadroyal.cn/?p=701) 了解基础概念。

LLVM 提供了多种Pass类, 均继承自 Pass class。都包含一些关键的虚函数，自定义 Pass 时需要重载这些函数。

介绍常用的 Pass 类及方法，其中比较常用的是 ModulePass 和  FunctionPass。

| 名称                | 解释                                                         | 接口                                                         |
| ------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| ImmutablePass       | 不常用的，指不运行, 不改变状态也永不更新的pass，一般情况下用于显示编译器的配置信息。 |                                                              |
| ModulePass          | 最常用的，将整个程序看作一个单元进行处理，可以引用，添加和删除 Function | `virtual bool runOnModule(Module &M) = 0;`                   |
| CallGraphSCCPass    | 可以从底至上遍历程序的函数调用关系图。                       | `virtual bool doInitialization(CallGraph &CG);`<br/>`virtual bool runOnSCC(CallGraphSCC &SCC) = 0;`<br/>`virtual bool doFinalization(CallGraph &CG);` |
| FunctionPass        | 可以修改和分析 Function 的行为，每个函数间是相互独立的, 相互之间无法影响。 | `virtual bool doInitialization(Module &M);`<br/>`virtual bool runOnFunction(Function &F) = 0;`<br/>`virtual bool doFinalization(Module &M);` |
| LoopPass            | 以循环为单位，以循环嵌套顺序处理，外层循环最后处理。可以使用 LPPassManager 接口更新循环嵌套。 | `virtual bool doInitialization(Loop *, LPPassManager &LPM);`<br/>`virtual bool runOnLoop(Loop *, LPPassManager &LPM) = 0;`<br/>`virtual bool doFinalization();` |
| RegionPass          | Region是一个控制流图的连接的子图，单入口单出口。可以被用来分析和优化控制流图中的部分内容。。使用 RGPassManager 接口可以更新  region tree。 | `virtual bool doInitialization(Region *, RGPassManager &RGM);`<br/>`virtual bool runOnRegion(Region *, RGPassManager &RGM) = 0;`<br/>`virtual bool doFinalization();` |
| MachineFunctionPass | 类似FunctionPass, 但它属于LLVM code generator(后端), 生成架构相关代码, FunctionPass 属于，生成通用的IR。无法通过通用Pass 接口注册 | `virtual bool runOnMachineFunction(MachineFunction &MF) = 0;` |

- 不同的 Pass 运行在不同的 XX(Module/Function/Loop..) 之上
- `runOnxx` 中通常为 Pass 的主要代码，在里面实现优化分析工作。
- `doInitialization` 顾名思义做一些初始化工作，`doFinalization` 做一些收尾工作。
- 如果这些虚函数修改工作，则返回  true,否则返回 false。



## Pass 注册

编写 Pass 后需要注册 Pass 到LLVM框架中。根据Pass作用域不同分为两种：

- 对于架构无关的，在 LLVM IR 层面的Pass
- 对于架构相关的优化Pass，在LLVM Backend层面的Pass，需要在目标后端目录下注册。

下面仅介绍常见的在LLVM IR 层面的注册。（在`lib/Passes/PassRegistry.def`目录可以查看 LLVM IR 优化pass. ）

通过 `RegisterPass`  template注册Pass。接口如下：

```c++
//其中第一参数 PassArg 通常代表Pass的名称，用于opt 工具识别 ，第二个参数是 Pass 的具体名称。
llvm::RegisterPass< passName >::RegisterPass	(	StringRef 	PassArg,
StringRef 	Name,
bool 	CFGOnly = false,
bool 	is_analysis = false 
)	
```

如果想要方便输出自定义 Pass 的信息，用于调试和分析，可以重载 print 函数，原型如下

```
virtual void print(llvm::raw_ostream &O, const Module *M) const;
```

使用 opt `-analyze` 可以调用该方法。其中参数 `llvm::raw_ostream` 指定需要输出结果的流，`Module`指定需要分析的上层 Module 的指针。



## Pass 间交互/依赖

LLVM Pass之间的依赖由PassManager管理的，如果自定义的 Pass 依赖其他 Pass，则需要实现 `getAnalysisUsage` 方法，获得 `AnalysisUsage` 对象。这个对象包含了 Pass 依赖的信息。	

```
virtual void getAnalysisUsage(AnalysisUsage &Info) const;
```

Pass 调用 AnalysisUsage 对象的以下方法之一解决依赖，安排指定Pass在自定义的Pass 之前运行。

- `AnalysisUsage::addRequired<>`  方法
- `AnalysisUsage::addRequiredTransitive<>`方法

- `AnalysisUsage::addPreserved<>` 方法

具体可以查看这篇文章: [【LLVM】Pass之间的依赖](https://www.jianshu.com/p/b280c8d67909) 

`getAnalysisUsage` 实现示例如下：

```c++
// This example modifies the program, but does not modify the CFG
void LICM::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesCFG(); // 保留 CFG
  AU.addRequired<LoopInfoWrapperPass>(); //等LoopInfoWrapperPass执行后再执行
}
```

-debug-pass 选项可以 debugging pass execution, seeing how things work, and diagnosing when you should be preserving more analyses than you currently are.





可以查看 PASS 依赖：

```
 opt sum-O0.ll -debug-pass=Structure -mem2reg -S -o sum-O1.ll 
```

Pass Arguments  可以看到。



### 优化

介绍用于不同优化的目的Pass。

#### 内存优化

#### 合并指令





### IR 层优化



- Ox 指定优化级别，具体有：

- O0 ： 不优化，用于代码调试

- O1 ：介于 O0 和 O2之间

- O2 ：中等优化

- Os ：类似于 O2 ，体积更小

- Oz ：类似于 Os ， 体积最小

- O3 ：类似于 O2 ，代码体积大于 O2，但是运行速度更快

- O4 ：类似于 O3 ，增加了链接时优化。

更多内置分析与优化Pass请查看文档 [LLVM’s Analysis and Transform Passes](http://llvm.org/docs/Passes.html#introduction) 

## 总结

以上内容介绍粗略地 Pass的编写/编译构建/运行等内容，内容比较浅显，想要真正地写一些有用的 Pass 还需要深入了解 LLVM 的接口。

PS：文章介绍的是传统的 Pass 编写方式，目前已有新版的PassManager，API 都有了变化，感兴趣的可以查看搜索 Writing LLVM Pass in 2018  系列的文章。
## 参考链接

1. [Writing an LLVM Pass](https://llvm.org/docs/WritingAnLLVMPass.html) 
2. [LLVM for Grad Students](https://www.cs.cornell.edu/~asampson/blog/llvm.html) 
3. [Run an LLVM Pass Automatically with Clang](https://www.cs.cornell.edu/~asampson/blog/clangpass.html) 
4. [初探LLVM&clang&pass](https://xz.aliyun.com/t/7257) 
5. [llvm学习（八）：Pass编写简单案例](https://www.leadroyal.cn/?p=719) 
6. [LLVM笔记(3) - PASS](https://www.cnblogs.com/Five100Miles/p/11025680.html) 
7. https://llvm.org/docs/Passes.html
8. 《LLVM cookbook》
9. https://llvm.org/devmtg/2014-04/PDFs/Talks/Passes.pdf