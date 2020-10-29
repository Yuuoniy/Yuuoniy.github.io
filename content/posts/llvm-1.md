---
title: "LLVM 入门教程之基本介绍"
date: 2020-06-16T09:39:11+08:00
tags: [llvm,pwn]
draft: false

---


## 前言

本篇文章作为LLVM入门教程，包括以下内容：

1. LLVM 的安装
2. LLVM 源码结构
3. LLVM 工具介绍
4. Clang 基本使用
5. LLVM IR 基本内容
6. Pass 介绍

## 安装

目前 LLVM 的最新版本为 10.0.0，我尝试通过预编译和源码编译两种安装方式安装了 LLVM+Clang。下面介绍这两种方式。

### 预编译源码安装

直接去官网下载解压即可，或者去[镜像网站]( https://mirrors.tuna.tsinghua.edu.cn/github-release/llvm/llvm-project/) 下载，根据系统选择压缩包进行下载，此处我选择的是 `clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz`  。

### 源码编译安装

首先下载相关源码，可以从 [github llvm-project](https://github.com/llvm/llvm-project) 选择自己需要的源码下载，也可以从上面的镜像网站下载。这里我从镜像网站下载了llvm 和 clang 源码（ [clang-10.0.0.src.tar.xz](https://mirrors.tuna.tsinghua.edu.cn/github-release/llvm/llvm-project/LLVM%2010.0.0/clang-10.0.0.src.tar.xz) 、[llvm-10.0.0.src.tar.xz](https://mirrors.tuna.tsinghua.edu.cn/github-release/llvm/llvm-project/LLVM%2010.0.0/llvm-10.0.0.src.tar.xz) )

然后将源码进行解压，保持其目录与 llvm-project 目录一致，即

```python
目录结构图：
llvm-project
   - llvm 
   - clang 
   - build
```

然后进入`llvm-project `目录编译，如果没有 cmake 可以直接通过 apt 安装一下。

```pyton
$ cd llvm-project
$ mkdir build && cd build
$ cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang" \
    -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" \
    -DBUILD_SHARED_LIBS=On ../llvm
$ make // 可以使用 -j 选项并行编译加速
```

- `-G` 指定为 `Unix Makefiles` 
- 使用 `DCMAKE_BUILD_TYPE` 选项指定编译的版本为 `Release`，一共有四种模式可选，分别为`Debug, Release, RelWithDebInfo`和`MinSizeRel`。使用 `Release` 可以节省空间，省略调试信息。
- `DLLVM_TARGETS_TO_BUILD` 指定目标平台的架构。
- `-DLLVM_ENABLE_PROJECTS`表明还需要编译的项目，这里指定 clang，可以根据需要加入其他子项目。
- `-DBUILD_SHARED_LIBS` 指定使用动态链接来链接LLVM的库，默认取值`Off`代表静态链接。

编译时间几十分钟至几小时不等。

安装结束后，在项目的bin目录下我们可以查看到许多二进制程序，包括 LLVM 相关工具以及 Clang 套件。

```python
# mm @ iZ2ze2gbki9vcb415a0z6rZ in /usr/local/llvm-project/build/bin 
$ ls
arcmt-test             lli                     llvm-itanium-demangle-fuzzer    llvm-reduce
bugpoint               lli-child-target        llvm-jitlink                    llvm-rtdyld
c-arcmt-test           llvm-addr2line          llvm-lib                        llvm-size
c-index-test           llvm-ar                 llvm-link                       llvm-special-case-list-fuzzer
clang                  llvm-as                 llvm-lipo                       llvm-split
clang++                llvm-bcanalyzer         llvm-lit                        llvm-stress
clang-10               llvm-cat                llvm-locstats                   llvm-strings
clang-check            llvm-cfi-verify         llvm-lto                        llvm-strip
clang-cl               llvm-config             llvm-lto2                       llvm-symbolizer
clang-cpp              llvm-cov                llvm-mc                         llvm-tblgen
...
```

## 架构

关于 LLVM 的架构设计，可以查看这篇文章：[LLVM](http://www.aosabook.org/en/llvm.html) 

## 源码结构

LLVM 的源码目录结构如下：

```
llvm/examples 使用LLVM IR 和 JIT的示例
llvm/include  LLVM library的公共头文件
llvm/lib      大部分源代码
llvm/projects 一些依赖LLVM的project
llvm/test     LLVM的测试套件，包含了很多测试用例
llvm/tools    LLVM 各个工具的源码，也是主要的用户接口。
llvm/utils    用于操作LLVM 源码的一些小工具
```

## 工具

安装好 LLVM 后，可以在 bin 目录中看到许多工具，如 `llc,lli` 等，可以在命令行输入`tool_name  -help`命令获取帮助，下面介绍常见的工具和基本的使用。

| 名称      | 介绍                                                         |
| --------- | ------------------------------------------------------------ |
| llvm-as   | 将 LLVM IR 文本格式转化为 bitcode 格式                       |
| llvm-dis  | 将 LLVM bitcode 文件转化为IR 文本格式(与llvm-as操作相反)     |
| llc       | 将 LLVM 字节代码转换成特定于平台的汇编代码                   |
| lli       | 通过解释器或使用高级选项中的即时 (JIT) 编译器直接执行字节代码 |
| opt       | LLVM optimizer，对LLVM IR 调用pass进行分析和优化，并且输出结果。 |
| llvm-link | 链接LLVM bitcode                                             |

### 使用

| 操作                             | 命令                                       |
| -------------------------------- | ------------------------------------------ |
| C code->LLVM IR                  | `clang -emit-llvm -S test.c -o test.ll`    |
| C code->LLVM bitcode             | `clang -emit-llvm -c test.c -o test.bc`    |
| LLVM IR -> LLVM bitcode          | `llvm-as test.ll –o test.bc`               |
| LLVM bitcode ->LLVM IR           | `llvm-dis test.bc -o test.ll`              |
| LLVM bitcode -> 目标机器汇编代码 | `llc test.bc –o test.s`                    |
| 变换 LLVM IR                     | `opt –passname input.ll –o output.ll`      |
| 链接 LLVM bitcode                | `llvm-link test1.bc test2.bc –o output.bc` |
| 执行 LLVM bitcode                | `lli output.bc`                            |

LLVM 自带了一些 Pass 例子，使用` -passname `（如 `-mem2reg`）即可指定 Pass, 也可以自己编写 Pass。

## Clang

Clang 是 LLVM 的前端之一， 可以用来编译C，C++，ObjectiveC 等语言。除此之外，LLVM 还有为Swift设计的编译器前端Swift等。

常见的 Clang 编译选项如下：

| 选项                | 解释                           |
| ------------------- | ------------------------------ |
| `-E, --preprocess`  | 只运行预处理阶段               |
| `-S, --assemble`    | 只运行预处理和编译阶段         |
| `-c, --compile`     | 只运行预处理、编译和汇编阶段。 |
| `-emit-llvm`        | 使用LLVM IR 描述汇编和目标文件 |
| `-ccc-print-phases` | 查看编译源文件各个阶段         |

可以通过 `clang -help` 获得选项帮助。

## LLVM  IR

LLVM  IR 是LLVM用于在编译器中表示代码的形式。 有三种表示格式：

| 格式                   | 介绍                                 |
| ---------------------- | ------------------------------------ |
| 文本格式（.ll 格式）   | 适合阅读                             |
| bitcode 格式(.bc 格式) | 适合机器存储的二进制文件             |
| 内存中格式             | 用于优化器查看和修改的内存中数据结构 |

IR 常见语法：

- **注释：**IR 注释以分号 (`;`) 开始，并持续到行末。
- **标识符:** 全局以 `@` 字符开始。所有的函数名和全局变量都必须以 `@` 开始。局部标识符以百分号 (`%`) 开始
- **整数类型**：LLVM 将整数类型定义为 `i*N*`，其中 *N* 是整数占用的字节数。
- **定义函数**：以关键字 `define` 开始，后面紧跟返回类型，然后是函数名。如 `define i32 @main() { ; some LLVM assembly code that returns i32 }`。 表示返回 32 字节整数的 `main` 函数
- **声明函数**：以关键字 `declare` 开始，后面紧跟着返回类型、函数名，以及该函数的可选参数列表。该声明必须是全局范围的。
- **函数返回**：有两种形式的返回语句：`ret  ` 或 `ret void`。
- **函数调用**：`call <function return type> <function name> <optional function arguments>`  如返回一个 6 位的整数并接受一个 36 位的整数的函数测试的语法如下：`call i6 @test( i36 %arg1 )`。

使用 IR 编写 helloworld 如下：

```python
declare i32 @puts (i8*)
@global_str = constant [13 x i8] c"Hello World!\00"
 
define i32 @main() {
  %temp = getelementptr [13 x i8]*  @global_str, i64 0, i64 0
  call i32 @puts(i8* %temp)
  ret i32 0
}
```

## Pass

Pass 是指针对 LLVM IR 的一次转换分析或优化。官方内置了很多Pass，关于它们的实现可以在 lib 目录下找到源码。`opt -help` 可以查看所有可用的内置pass。

Pass 可以分为三类：

- `Analysis Passes:` 用于计算分析和输出IR信息
- `Transform Passes:` 对IR 进行实际的操作，转换 IR。
- `Utility Passes`：一些小工具，本质既不是分析也不是转化。

此外，不同优化基本使用的内置 pass 也不同，可以通过一下命令查看：

`llvm-as < /dev/null | opt -O3 -disable-output -debug-pass=Arguments`

针对上述命令，我的机器跑出的结果如下：

```python
$ llvm-as < /dev/null | opt -O3 -disable-output -debug-pass=Arguments
Pass Arguments:  -tti -tbaa -scoped-noalias -assumption-cache-tracker -targetlibinfo -verify -ee-instrument -simplifycfg -domtree -sroa -early-cse -lower-expect
Pass Arguments:  -targetlibinfo -tti -tbaa -scoped-noalias -assumption-cache-tracker -profile-summary-info -forceattrs -inferattrs -domtree -callsite-splitting -ipsccp -called-value-propagation -attributor -globalopt -domtree -mem2reg -deadargelim -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -simplifycfg -basiccg -globals-aa -prune-eh -inline -functionattrs -argpromotion -domtree -sroa -basicaa -aa -memoryssa -early-cse-memssa -speculative-execution -basicaa -aa -lazy-value-info -jump-threading -correlated-propagation -simplifycfg -domtree -aggressive-instcombine -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -libcalls-shrinkwrap -loops -branch-prob -block-freq -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -pgo-memop-opt -basicaa -aa -loops .....
```

一些比较重要的内置 Pass,如下：

```
adce： Aggressive Dead Code Elimination 入侵式无用代码消除  
bb-vectorize：Basic-Block Vectorization 基本块向量化
constprop：Simple constant propagation 简单常量传播
dce：Dead Code Elimination 无用代码消除
deadargelim：Dead Argument Elimination 无用参数消除
globaldce：Dead Global Elimination 无用全局变量消除
globalopt：Global Variable Optimizer 全局变量优化
gvn：Global Value Numbering 全局变量编号
inline：Function Integration/Inlining 函数内联
instcombine：Combine redundant instructions 冗余指令合并
licm：Loop Invariant Code Motion 循环常量代码外提
loop-unswitch：Unswitch loops 循环外提
loweratomic：Lower atomic intrinsics to non-atomic form 原子内建函数lowering
lowerinvoke：Lower invokes to calls, for unwindless code generat invode指令lowering
lowerswitch：Lower SwitchInsts to branches switch指令lowering
mem2reg：Promote Memory to Register 内存访问优化
memcpyopt：MemCpy Optimization MemCpy优化
simplifycfg：Simplify the CFG 简化CFG
tailcallelim：Tail Call Elimination 尾调用消除
```

[llvm](https://github.com/llvm/llvm-project/tree/master/llvm)/[test](https://github.com/llvm/llvm-project/tree/master/llvm/test)/[Transforms](https://github.com/llvm/llvm-project/tree/master/llvm/test/Transforms) 提供了Pass 对应的测试样例，可以自己使用 opt 尝试跑一下，查看IR 文件有哪些变化，以便更好地理解这些pass。

此外，LLVM 允许开发人员在程序编译生命周期的不同部分自定义Pass（如寄存器分配前后）。 LLVM 使用 PassManager  来注册，调度和管理 Pass 之间的依赖关系。

## 总结

本文作为LLVM的入门篇，主要介绍了 LLVM 安装/工具/结构/LLVM IR/Pass 等内容，后续会随着学习不断地深入介绍其他内容。

## 参考资料

1. [LLVM Pass入门导引](https://zhuanlan.zhihu.com/p/122522485 )
2. [LLVM IR tutorial](https://llvm.org/devmtg/2019-04/slides/Tutorial-Bridgers-LLVM_IR_tutorial.pdf)
3. [LLVM入门篇剧场版](https://zhuanlan.zhihu.com/p/65818158) 
4. [LLVM Language Reference Manual](https://llvm.org/docs/LangRef.html) 
5. [使用 LLVM 框架创建有效的编译器，第 2 部分](https://www.ibm.com/developerworks/cn/opensource/os-createcompilerllvm2/index.html) 
6. [使用 LLVM 框架创建一个工作编译器，第 1 部分](https://www.ibm.com/developerworks/cn/opensource/os-createcompilerllvm1/)
7. [Clang 11 documentation](https://clang.llvm.org/docs/index.html#)
8. [LLVM Tutorial](http://llvm.org/docs/tutorial/)/[中文版](https://llvm-tutorial-cn.readthedocs.io/en/latest/index.html#)
9. [Getting Started with the LLVM System](http://llvm.org/docs/GettingStarted.html#getting-started) 

