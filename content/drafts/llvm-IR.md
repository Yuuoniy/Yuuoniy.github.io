---
draft: true
---
# LLVM IR 层介绍

## 前言

LLVM IR 是 LLVM 的中间语言，先前的文章包括了 IR 的简单介绍，本篇文章针对  IR深入学习。

包括以下内容：

- LLVM IR 特性

- IR 语法

- 生成 IR

  
## 格式

IR是SS A静态单一赋值的（Static Single Assignment）。 

LLVM IR 是强类型语言。文档 LangRef

## SSA

“alloca + mem2reg”技术

## 语法

结合例子分析语法，

首先编写程序

```c
int sum(int a,int b){
	return a+b;
}
```

编译转化为 LLVM IR

```c++
clang sum.c -emit-llvm -S -c -o sum.ll
```

得到 ll 文件：

```python
$ cat sum.ll
; ModuleID = 'sum.c'
source_filename = "sum.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @sum(i32 %0, i32 %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, i32* %3, align 4
  store i32 %1, i32* %4, align 4
  %5 = load i32, i32* %3, align 4
  %6 = load i32, i32* %4, align 4
  %7 = add nsw i32 %5, %6
  ret i32 %7
}

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.0 "}

```

下面结合该文件介绍语法

target datalayout: 第一字母表示端序。

以 type:<size>:<abi>:<preferred> 提供类型信息

attributes #0 表示使用

alloca 表示在栈上分配空间。通常会接一个对齐量。

```
%a.addr 
```

最上方的 target datalayout 和 target triple 描述了目标机器的字节序、类型大小等信息，如指针位宽、首选对齐方式等。

nsw 是 no signed wrap 的缩写，类似的还有 nuw，no unsigned wrap，表示已知不会溢出，因此允许进行一些优化。

一些常用的指令

#### 转变指令

The ‘`bitcast`‘ instruction converts `value` to type `ty2` without changing any bits.

```
<result> = bitcast <ty> <value> to <ty2>             ; yields ty2
```


icmp 指令

```
<result> = icmp <cond> <ty> <op1>, <op2>   ; yields i1 or <N x i1>:result
```


#### 结束指令

br 指令

```ir
br i1 <cond>, label <iftrue>, label <iffalse>
br label <dest>          ; Unconditional branch
```

The ‘`br`‘ instruction is used to cause control flow to transfer to a different basic block in the current function. There are two forms of this instruction, corresponding to a conditional branch and an unconditional branch.

#### 内存访问






#### 参数属性 

```
nocapture
```

This indicates that the callee does not make any copies of the pointer that outlive the callee itself. This is not a valid attribute for return values. Addresses used in volatile operations are considered to be captured.



```
phi 
```



#### 函数属性





## Aggregate Types



IR的Aggregate Types包括数组和结构体。





## getelementptr

我们可以使用 `getelementptr`指令来获得指向数组的元素和指向结构体成员的指针。

示例：

## 布局



### LLVM IR in-memory model

LLVM IR 的内存中表示模型与LLVM 语法模型相似， 相关类在 include/llvm/IR 下定义。下面介绍几个比较重要的类：

- Module 类 

可以通过 Module::iterator 遍历

- Functions 类

  既可以表示函数声明也可以表示函数定义，

通过 getArgumentList() 获取参数列表。也可以通过迭代器 Function::arg_iterator 的 arg_begin() 和 arg_end() 遍历。

如果 Function 对象为函数定义，那么通过 ` for (Function::iterator i = function. begin(), e = function.end(); i != e; ++i) ` 可以遍历基本块。

- BasicBlock 类

  包含 LLVM 的指令序列，可以通过  begin()/end() 访问。通过 getTerminator() 接口可以直接访问基本块的最后一个指令。通过  getSinglePredecessor() 访问前继单个基本块。如果该基本块的predecessor不止一个，则需要自己手动获取 所有 predecessors。这可以通过遍历基本块并检查最后的指令实现。

-  Instruction 类

表示 LLVM IR 的原子，单个指令。

他提供一些方法访问 high-level predicates ，如 isAssociative(), isCommutative(), isIdempotent(), or isTerminator() 。最主要的方法为 getOpcode()，返回 llvm::Instruction  枚举类，代表着 LLVM IR opcodes。可以通过  op_begin() 和  op_end() 访问。

下面介绍 LLVM IR 最强大的接口： Value 和 User 接口。通过他们可以方便浏览 use-def 和 def-use 链。

Value 子类通常代表一个结果，可以被其他对象使用。User 子类代表一个实体，其中包含了 Value 的接口。

 Function 和Instruction 同时是 Value 和User的子类, BasicBlock 是 Value的子类。

下面详细介绍这两个类：

- Value 类：
   定义了use_begin() 和 use_end() 方法，可以遍历Users获取 def-use 链。
  每个 LLVM value 都有一个唯一的标识符，如 %add1 标识  add 指令的结果，BB1 代表一个基本块。myfunc 代表一个函数。 使用 getName() 接口获取名字；
  
  方法replaceAllUsesWith(Value *) 可以对所有使用该 Value 的 users 替换为其他 Value。
  
  这是SSA的一个优点，可以很方便地进行指令替换和速度优化。

- User 类：
  通过方法op_begin() 和 op_end()可以快速获取该 User 类使用的所有 Value 接口。这表示 use-def 链。可以使用 replaceUsesOfWith(Value *From, Value *To) 接口来替换该类使用的任意值。

# 编写自定义LLVM IR生成器

我们可以使用 LLVM IR 生成器 API 来构建 IR, 首先了解一下涉及的头文件。

| 文件                                      | 说明                                                    |
| ----------------------------------------- | ------------------------------------------------------- |
| #include <llvm/ADT/SmallVector.h>         | 可以使用 SmallVector<>  模板，帮助我们有效地构建数组。  |
| #include <llvm/Analysis/Verifier.h>:      | verifier  pass  用于检查LLVM module 是否遵循 IR rules。 |
| #include <llvm/IR/BasicBlock.h>:          | 声明 BasicBlock  类                                     |
| #include <llvm/IR/CallingConv.h>:         | 该文件包含一系列有关函数调用的 ABI，如在哪存储函数参数  |
| #include <llvm/IR/Function.h>:            | 定义 Function 类                                        |
| #include <llvm/IR/Instructions.h>:        | 声明了所有 Instruction  的子类。                        |
| #include <llvm/IR/LLVMContext.h>:         | 存储了 LLVM 库 的全局数据，允许多线程实现。             |
| #include <llvm/IR/Module.h>:              | 声明 Module  类                                         |
| #include <llvm/Bitcode/ReaderWriter.h>:   | 允许读写 LLVM bitcode 文件                              |
| #include <llvm/Support/ToolOutputFile.h>: | 声明了用于写入到文件的工具类                            |

 

关于 LLVM 接口/数据结构等更多介绍可以查看文档 http://llvm.org/docs/ProgrammersManual.html





### 参考资料

1. [A Tour to LLVM IR (上)](https://zhuanlan.zhihu.com/p/66793637)
2. [Intro to LLVM IR](http://blog.wangluyuan.cc/2020/03/28/intro-to-llvm-ir/) 
3. [Create a working compiler with the LLVM framework, Part 1](https://www.ibm.com/developerworks/opensource/library/os-createcompilerllvm1/index.html) 
4. http://llvm.org/docs/ProgrammersManual.html
5. https://segmentfault.com/p/1210000009435800/read
6. https://llvm-tutorial-cn.readthedocs.io/en/latest/
7. https://blog.csdn.net/qq_29674357/article/details/78731713
8. https://readthedocs.org/projects/mapping-high-level-constructs-to-llvm-ir/downloads/pdf/latest/

