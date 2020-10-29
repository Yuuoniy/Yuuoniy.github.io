---
draft: true
---
# LLVM 入门教程之外部项目

本文内容介绍 LLVM 的相关项目，这些项目不包括在 LLVM+Clang, 因此需要额外安装，具体包括：

- Clang extra tools
- Compiler-RT
- DragonEgg
- LLVM test suite
- LLDB
- libc++

此外，还有两个官方 LLVM 项目：Polly 和 lld，本文不涉及。

## 安装

先去官网或镜像网站下载对应的源码，然后把源码放到对应目录后进行编译安装，具体的目录如下：

```
Compiler-RT: llvm/projects/compiler-rt

```





## Compiler-RT





## DragonEgg





## LLVM test suite





## LLDB



LLBD 是使用 LLVM 基础架构构建的调试器，相当于 gdb。

LLBD 依赖swig、libedit、python。首先需要通过以下命令安装:

```
sudo apt get install swig libedit-dev python
```



## libc++ 标准库



libc ++ 是 LLVM 项目重写的C++ 标准库，支持最新的C++标准。

## 参考资料

1. [lldb  Tutorial](https://lldb.llvm.org/use/tutorial.html)
2. 