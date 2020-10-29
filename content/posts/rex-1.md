---
title: "Rex: 自动化利用引擎分析"
date: 2020-02-11T09:39:11+08:00
draft: false
---
# Rex: 自动化利用引擎分析
> 文章首发于 [先知社区](https://xz.aliyun.com/t/7117)

## 前言

最近在看 rex，没有官方文档，已有的教程也有点过时，基本只能通过看源码学习。

本篇教程当作是学习的记录，也希望能帮助研究 AEG 的同学快速上手 rex，对 rex 的架构和使用方式有个整体的认识。

## 概述

Rex 是  [Shellphish](http://shellphish.net/cgc/) 团队开发的自动生成 exploit 的引擎，是 [Mechaphish](https://github.com/mechaphish) 中的一个模块，最初用于 [CGC](https://ma3k4h3d.top/2018/11/01/CGC/) 竞赛。

Rex 基于硬件模拟器 QEMU 和 angr ，通过混合执行（Concolic Execution）复现崩溃路径，根据寄存器及内存信息对漏洞类型/可利用性进行判定等，并尝试应用多种漏洞利用技术自动生成利用脚本。

本篇文章会介绍 rex 安装/顶层接口/内部实现/相关依赖等内容。

## 安装

有两种方法

1. 安装 rex 及其依赖  
2. 直接安装 mechaphish 镜像

推荐直接使用  `shellphish/mechaphish` docker 镜像，比较方便

```shell
docker pull shellphish/mechaphish; 
docker run -it shellphish/mechaphish
```

rex 基于 angr，关于 angr 的使用方式，可以查看我的另一篇[教程](https://xz.aliyun.com/t/7117)。

## 测试

首先测试一下 rex 是否安装成功，简单测试代码如下：

```python
tg = archr.targets.LocalTarget(<path_to_binary>, target_os='cgc')
crash = rex.Crash(tg, <input>)
```

首先需要创建 target ,类型是  `archr.targets.Target` 并指定配置。

接下来通过 rex.Crash 接口，传递创建的 target 和可以触发 crash 的输入，我们可以获得 Crash 对象，便可以对 Crash 对象进行一系列分析，下面会涉及对 Crash 对象的操作。

这里 `path_to_binary` 为二进制文件路径，target_os 指定系统，cgc 或者 linux, 这里我们可以使用 cgc 的文件进行测试（可以在[binaries](https://github.com/angr/binaries) 中找到）

简单测试：

```python
t = archr.targets.LocalTarget(["/home/angr-dev/binaries/tests/defcon24/legit_00003"], target_os='cgc')
crash = rex.Crash(t, b"\x00\x0b1\xc1\x00\x0c\xeb\xe4\xf1\xf1\x14\r\rM\r\xf3\x1b\r\r\r~\x7f\x1b\xe3\x0c`_222\r\rM\r\xf3\x1b\r\x7f\x002\x7f~\x7f\xe2\xff\x7f\xff\xff\x8b\xc7\xc9\x83\x8b\x0c\xeb\x80\x002\xac\xe2\xff\xff\x00t\x8bt\x8bt_o_\x00t\x8b\xc7\xdd\x83\xc2t~n~~\xac\xe2\xff\xff_k_\x00t\x8b\xc7\xdd\x83\xc2t~n~~\xac\xe2\xff\xff\x00t\x8bt\x8b\xac\xf1\x83\xc2t~c\x00\x00\x00~~\x7f\xe2\xff\xff\x00t\x9e\xac\xe2\xf1\xf2@\x83\xc3t")
```

如果没有出现报错则说明安装成功。

rex 也提供了多种测试样例, 可以在 tests 目录查看, 测试使用的文件可以在 [binaries 仓库]( https://github.com/angr/binaries ) 中找到. 



## 顶层接口

使用 rex 通常步骤：

1. 创建 target 对象，随后使用 target 和 input 创建 Crash 对象
2. 对 Crash 进行分析，调用 explore 探索路径，调用 exploit() 方法构建 exp
3. 获取 exploit 相关信息，导出到文件等

此外也可以对 state 添加约束进行求解等，自行探索。

### Crash 对象

属性

```
- crash_types 返回 crash 的漏洞类型
```

方法

```
- explorable()  Determine if the crash can be explored with the 'crash explorer'.
- exploitable() Determine if the crash is exploitable.
- exploit() 返回一个 ExploitFactory  实例，用于管理和构建 exp
- explore() explore a crash further to find new bugs
- memory_control()  determine what symbolic memory we control which is at a constant address
- stack_control()  determine what symbolic memory we control on the stack.
- copy() 拷贝 crash 对象
- checkpoint()   Save intermediate results (traced states, etc.) to a file 
- checkpoint_restore() 
```



### ExploitFactory  

通过 crash 的 exploit 方法我们可以获得 ExploitFactory  实例，用于管理和构建 exploit。

ExploitFactory  有一个重要的属性 arsenal，是一个字典，用来存储对应 technique 的 exploit, 关于 rex 中实现的 technique 后面会涉及。



### Vulnerability

rex 定义了如下几种漏洞：

```python
    IP_OVERWRITE              = "ip_overwrite"
    PARTIAL_IP_OVERWRITE      = "partial_ip_overwrite"
    UNCONTROLLED_IP_OVERWRITE = "uncontrolled_ip_overwrite"
    BP_OVERWRITE              = "bp_overwrite"
    PARTIAL_BP_OVERWRITE      = "partial_bp_overwrite"
    WRITE_WHAT_WHERE          = "write_what_where"
    WRITE_X_WHERE             = "write_x_where"
    UNCONTROLLED_WRITE        = "uncontrolled_write" # a write where the destination address is uncontrolled
    ARBITRARY_READ            = "arbitrary_read"
    NULL_DEREFERENCE          = "null_dereference"
    ARBITRARY_TRANSMIT        = "arbitrary_transmit" # transmit where the buf argument is completely controlled
    ARBITRARY_RECEIVE         = "arbitrary_receive" # receive where the buf argument is completel controlled
```





## 内部解读

Rex 内部实现主要包含三个模块:

- Crash：重现崩溃路径，包括漏洞类型判定,  Crash 的可利用性判定等；
- Technique：对于可利用的 Crash，采取相应的利用技术，构造 Exploit；
- Exploit：调用各子模块，自动生成 Exploit

可以简单理解成 crash + technique = exploit ,下面我们来看具体内容



### crash 分析

导入 crash 后，首先对 crash 进行 trace、筛选内存写操作和 判定漏洞类型。对应的函数分别为 `_trace / _filter_memory_writes /  _triage_crash` 

接下来我们对这三个函数进行分析：

#### 路径重现（tracing)

函数：  _trace 

使用给定的输入，通过符号执行，重现路径，如果没有 Crash 会抛出 NonCrashingInput  异常.

首先使用用户输入获得具体的 trace，

```python
  # collect a concrete trace
   save_core = True
   if isinstance(self.tracer_bow, archr.arsenal.RRTracerBow):
       save_core = False
   r = self.tracer_bow.fire(testcase=test_case, channel=channel,save_core=save_core)
```

再进行符号化 trace

```python
self._t = r.tracer_technique(keep_predecessors=2, copy_states=False, mode=TracingMode.Strict)
simgr.use_technique(self._t)
simgr.use_technique(angr.exploration_techniques.Oppologist())
```

结束 trace, 检查是否有 crash

```python
        # tracing completed
        # if there was no crash we'll have to use the previous path's state
        if 'crashed' in simgr.stashes:
            # the state at crash time
            self.state = simgr.crashed[0]
            # a path leading up to the crashing basic block
            self.prev = self._t.predecessors[-1]
        else:
            self.state = simgr.traced[0]
            self.prev = self.state
```



#### 获得内存写操作

 `_filter_memory_writes`  获得所有的写内存操作，并将分成符号内存（ symbolic memory bytes ）和 flag 内存（ flag memory bytes ）。flag memory 针对的是 cgc 格式文件，其他情况下为空。

```python
    def _filter_memory_writes(self):
        memory_writes = sorted(self.state.memory.mem.get_symbolic_addrs())
        if self.is_cgc:
            # remove all memory writes that directly end up in the CGC flag page (0x4347c000 - 0x4347d000)
            memory_writes = [m for m in memory_writes if m // 0x1000 != 0x4347c]
        user_writes = [m for m in memory_writes if
                       any("aeg_stdin" in v for v in self.state.memory.load(m, 1).variables)]
        if self.is_cgc:
            flag_writes = [m for m in memory_writes if
                           any(v.startswith("cgc-flag") for v in self.state.memory.load(m, 1).variables)]
        else:
            flag_writes = []
        l.debug("Finished filtering memory writes.")
        self.symbolic_mem = self._segment(user_writes)
        self.flag_mem = self._segment(flag_writes)
```



#### 漏洞类型判断(triage_crash)

rex 中  `_triage_crash`  函数用于判断 crash 对应的漏洞类型，漏洞类型之后的可利用性判定

漏洞判断基本思路如下：

1. 检查 ip 是否符号化（即ip是否可控），并且检查可控的大小。通过此我们可以将漏洞判定为 `IP_OVERWRITE / PARTIAL_IP_OVERWRITE`。
2. 检查 bp 是否符号化，并且检查可控的大小，通过此我们可以漏洞判定为 `BP_OVERWRITE / PARTIAL_BP_OVERWRITE`
3. 检查触发崩溃时前一个 State，查看最近的操作（ recent_actions ）筛选出内存读写地址可控的操作，得到数组  `symbolic_actions`
4. 如果符号化操作中有内存写，则判断写数据是否可控，通过此我们可以将漏洞判定为  `WRITE_WHAT_WHERE /  WRITE_X_WHERE` 。
5. 如果符号化操作中有内存读，我们可以将漏洞判定为   `ARBITRARY_READ`  。

以下截取该函数的部分内容帮助理解：

```python
	 # 判断 ip 是否可控，bp 类似        
    if self.state.solver.symbolic(ip): 
        # how much control of ip do we have?
        if self._symbolic_control(ip) >= self.state.arch.bits:
            l.info("detected ip overwrite vulnerability")
            self.crash_types.append(Vulnerability.IP_OVERWRITE)
        else:
            l.info("detected partial ip overwrite vulnerability")
            self.crash_types.append(Vulnerability.PARTIAL_IP_OVERWRITE)
            
        return
```

```python
        # 筛选出目的地址可控的操作
    	# grab the all actions in the last basic block
        symbolic_actions = [ ]
        if self._t is not None and self._t.last_state is not None:
            recent_actions = reversed(self._t.last_state.history.recent_actions)
            state = self._t.last_state
            # TODO: this is a dead assignment! what was this supposed to be?
        else:
            recent_actions = reversed(self.state.history.actions)
            state = self.state
        for a in recent_actions:
            if a.type == 'mem':
                if self.state.solver.symbolic(a.addr.ast):
                    symbolic_actions.append(a)
              
```

```python
        #判断是内存读还是内存写，并判断数据是否可控，由此确定漏洞类型
    	for sym_action in symbolic_actions:
            if sym_action.action == "write":
                if self.state.solver.symbolic(sym_action.data):
                    l.info("detected write-what-where vulnerability")
                    self.crash_types.append(Vulnerability.WRITE_WHAT_WHERE)
                else:
                    l.info("detected write-x-where vulnerability")
                    self.crash_types.append(Vulnerability.WRITE_X_WHERE)

                self.violating_action = sym_action
                break

            if sym_action.action == "read":
                # special vulnerability type, if this is detected we can explore the crash further
                l.info("detected arbitrary-read vulnerability")
                self.crash_types.append(Vulnerability.ARBITRARY_READ)

                self.violating_action = sym_action
                break
```

完成漏洞类型判定后，我们会对 crash 进行一些判断如 `explorable/leakable`，如 explore 目的是寻找一个更有价值的 crash, 方便漏洞利用。

#### explore 

首先判断 crash 是否可 explore, 可以 explore 的漏洞类型是: `ARBITRARY_READ/WRITE_WHAT_WHERE/WRITE_X_WHERE`

```python
    def explorable(self):
        explorables = [Vulnerability.ARBITRARY_READ, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]
        return self.one_of(explorables)
```

explore 主要针对任意内存读写漏洞，对应两种实现：`_explore_arbitrary_read` 和 `_explore_arbitrary_write`。

```python
        if self.one_of([Vulnerability.ARBITRARY_READ]):
                self._explore_arbitrary_read(path_file)
        elif self.one_of([Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]):
            self._explore_arbitrary_write(path_file)
        else:
            raise CannotExplore("unknown explorable crash type: %s" % self.crash_types)
```

`_explore_arbitrary_read / _explore_arbitrary_write` 进行路径探索，分别对应任意写和任意读漏洞，使读写的地址是符号化地址，即我们可控的 ( point the violating address at a  symbolic memory region )，返回一个 crash 对象。



#### 可利用性判定

通过调用 exploitable 接口判断 crash 是否可利用，rex 会判断 Crash 的漏洞类型是否属于可 exploitable 漏洞之一 。

```python
def exploitable(self):
        exploitables = [Vulnerability.IP_OVERWRITE, Vulnerability.PARTIAL_IP_OVERWRITE, Vulnerability.BP_OVERWRITE,
                Vulnerability.PARTIAL_BP_OVERWRITE, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]
        return self.one_of(exploitables)

```

检查是否可以泄露信息, 判断 crash 类型是否属于 `ARBITRARY_READ/ARBITRARY_TRANSMIT` 其中一种.



### Technique 对象

每个 technique 都是  Technique 对象的子类, 主要对 check / apply 这两个接口进行重写. 同时 Technique 对象实现了一些通用的接口, 作为构造 exploit 的辅助函数. 

下面介绍一下 check / apply

```
check: 检查对于给定的crash, 该技术能否应用到 binary 上,返回布尔值

apply : 在binary的崩溃状态点应用该技术,返回 Exploit 对象或抛出  CannotExploit  异常
```

apply 其实就是根据每个技术的不同，添加不同的约束。



每种包含  applicable_to  属性,表示可以应用的平台, unix 或者 cgc

以下是 technique 的基本信息, 基本通过名称就能知道攻击技术，就不一一介绍了，它们的实现也比较朴素。

| 名称                          | 限定漏洞类型                        | 其他条件                       | 平台 |
| ----------------------------- | ----------------------------------- | ------------------------------ | ---- |
| `call_jmp_sp_shellcode`       | IP_OVERWRITE / PARTIAL_IP_OVERWRITE | 栈可执行                       | unix |
| `call_shellcode`              | IP_OVERWRITE / PARTIAL_IP_OVERWRITE | 栈可执行                       | unix |
| circumstantially_set_register | IP_OVERWRITE / PARTIAL_IP_OVERWRITE |                                | cgc  |
| `rop_leak_memory`             | IP_OVERWRITE / PARTIAL_IP_OVERWRITE |                                | cgc  |
| `rop_register_control`        | IP_OVERWRITE / PARTIAL_IP_OVERWRITE |                                | unix |
| `rop_set_register`            | IP_OVERWRITE / PARTIAL_IP_OVERWRITE |                                | cgc  |
| `rop_to_accept_system`        | IP_OVERWRITE / PARTIAL_IP_OVERWRITE | 存在 accept& read函数          | unix |
| `rop_to_execl`                | IP_OVERWRITE/PARTIAL_IP_OVERWRITE   | 存在 execl&dup2 函数           | unix |
| `rop_to_system`               | IP_OVERWRITE / PARTIAL_IP_OVERWRITE | 存在 system 函数               | unix |
| `rop_to_system_complicated`   | IP_OVERWRITE / PARTIAL_IP_OVERWRITE | libc 被加载& system 函数 & plt | unix |
| `shellcode_leak_address`      | IP_OVERWRITE / PARTIAL_IP_OVERWRITE | 栈可执行                       | cgc  |
| `shellcode_set_register`      | IP_OVERWRITE / PARTIAL_IP_OVERWRITE | 栈可执行                       | cgc  |

可以在调用 exploit 时设置  `blacklist_techniques`  参数排除不需要使用的技术. 

成功应用 Technique 会返回 Exploit 对象，接下来介绍 Exploit 对象。

### Exploit  对象

> An Exploit object represents the successful application of an exploit technique to a crash state. 

rex 实现了 `ExploitFactory`  类，用于管理和构建 exploit, 

调用 exploit() 方法时，`ExploitFactory`  会依次应用每一种利用技术, 尝试生成 exploit, 得到的  exploit  会以`arsenal[<techinique_name>]`  形式存储在 arsenal 属性中. 针对 CGC 实现了  [CGCExploitFactory]( https://github.com/angr/rex/blob/0df09e0bc0a8a64b876ce366e3202998bd58b8f0/rex/exploit/cgc_exploit_factory.py#L8 ) 类.

构建 exp:

```python
 def exploit(self, blacklist_symbolic_explore=True, **kwargs):
        """
        Initialize an exploit factory, with which you can build exploits.
        :return:    An initialized ExploitFactory instance.
        :rtype:     ExploitFactory
        """
        factory = self._prepare_exploit_factory(blacklist_symbolic_explore, **kwargs)
        factory.initialize()
        return factory
    
    
    
```

`_prepare_exploit_factory` 函数主要为 exploit 的生成做一些准备操作，比如设置 technique 的黑名单，判断输入类型等。

### 测试

以下是分别对 cgc 和 linux 两种格式的测试样例

#### cgc

```python
def test_legit_00003():
    # Test exploration and exploitation of legit_00003.
    inp = b"1\n" + b"A" * 200 #设置输入内容
    path = os.path.join(bin_location, "tests/defcon24/legit_00003")
    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, inp, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'legit_00003'))
 
        nose.tools.assert_true(crash.explorable())  #判断是否可以 explore
        nose.tools.assert_true(crash.one_of(Vulnerability.WRITE_WHAT_WHERE)) # 漏洞是否为任意写

        crash.explore() #进行探索m
        arsenal = crash.exploit(blacklist_techniques={'rop_set_register', 'rop_leak_memory'})

        nose.tools.assert_true(len(arsenal.register_setters) >= 2)
        nose.tools.assert_true(len(arsenal.leakers) >= 1)

        crash.project.loader.close()

        for reg_setter in arsenal.register_setters:
            nose.tools.assert_true(_do_pov_test(reg_setter))

        for leaker in arsenal.leakers:
            nose.tools.assert_true(_do_pov_test(leaker))
```



#### linux

```python
def test_linux_stacksmash_32():
    # Test exploiting a simple linux program with a stack buffer overflow. We should be able to exploit the test binary by
    # ropping to 'system', calling shellcode in the BSS and calling 'jmpsp' shellcode in the BSS.

    inp = b"A" * 227
    lib_path = os.path.join(bin_location, "tests/i386")
    ld_path = os.path.join(lib_path, "ld-linux.so.2")
    path = os.path.join(lib_path, "vuln_stacksmash")
    with archr.targets.LocalTarget([ld_path, '--library-path', lib_path, path], path, target_arch='i386').build().start() as target:
        crash = rex.Crash(target, inp, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'vuln_stacksmash'))

        exploit = crash.exploit(blacklist_techniques={'rop_leak_memory', 'rop_set_register'})
        crash.project.loader.close()

        # make sure we're able to exploit it in all possible ways
        assert len(exploit.arsenal) == 3
        assert 'rop_to_system' in exploit.arsenal
        assert 'call_shellcode' in exploit.arsenal
        assert 'call_jmp_sp_shellcode' in exploit.arsenal

        _check_arsenal_has_send(exploit.arsenal)
```

### 相关库

这里顺便介绍一些 rex 依赖的 [archr](https://github.com/angr/archr)  模块

#### archr

前面提到，在使用 rex 前，需要使用 archr 创建 target 对象。我们可以指定  `target_path /  target_os(linux /cgc)  /  target_arch(linux , x86_64)` 等.

archr 模块实现了以 target 为中心的分析模型。（传统是以程序 program 为中心）

其中包含两个重要的概念，

Targets: 包含 target 的说明，如何配置，如何启动以及如何交互。

Bows：明确 target 特定的分析动作，包括 tracing，符号执行（symbolic execution）等，为了实现目标，Bows 可能会注入 `Arrows` （如`qemu-user`, `gdbserver`等）到 target 中。

archr 提供了两种 target:

- `DockerImageTarget`: docker 镜像
- `LocalTarget`：本地系统运行的 target

提供了以下 Bows ：

| 名称             | 描述                                 |
| ---------------- | ------------------------------------ |
| `DataScoutBow`   | 获取进程启动时的内存映射，环境，属性 |
| `AngrProjectBow` | 创建 angr Project                    |
| `AngrStateBow`   | 创建 angr State                      |
| `QEMUTraceBow`   | 执行 qemu tracing                    |
| `GDBServerBow`   | 在 gdbserver 中启动 target           |
| `STraceBow`      | strace 目标（即跟踪系统调用和信号）  |
| `CoreBow`        | 启动target 并恢复 core               |
| `InputFDBow`     | 确定用户输入的FD数目                 |

具体使用方法可以查看项目。



#### 总结

对于自动化利用，rex 比较简陋，漏洞利用技术也比较简单，但是我们可以学习它的思路，对其进行改进。



## 参考链接

1.  [https://paper.seebug.org/papers/Security%20Conf/Hitcon/Hitcon-2016/1202%20R2%201510%20automatic%20binary%20exploitation%20and%20patching%20using%20mechanical%20shellphish.pdf](https://paper.seebug.org/papers/Security Conf/Hitcon/Hitcon-2016/1202 R2 1510 automatic binary exploitation and patching using mechanical shellphish.pdf) 
2.  https://ma3k4h3d.top/2019/01/23/rex-crash/ 
3.  https://ma3k4h3d.top/2019/03/28/rex-1/ 
4.  https://ma3k4h3d.top/2019/01/17/Rex-stacksmash/ 
5.   https://github.com/angr/rex 

