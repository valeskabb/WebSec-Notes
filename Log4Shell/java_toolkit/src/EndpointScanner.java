import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 端点扫描器
 * 三个步骤：
 * 1. 探测端口是否存活（用 TCP connect）
 * 2. 枚举 Solr 管理接口：/solr/admin/cores（core 列表）、/solr/admin/info/system（系统信息）
 * 3. 从系统信息提取 JVM 版本并判断 Log4Shell 是否可以利用靶机 1.8.0_102 --> JDK 1.8.0_191 之前 LDAP 远程 codebase 加载默认开启
 *    (8u191+ 起 trustURLCodebase 默认 false，LDAP 这种情况下注入链失效)
 *
 * 所有 HTTP 请求都用原始 Socket 发送：可以保证路径中的 ${..} 等字符不被做 URL 编码
 */
public class EndpointScanner {

    private static final int MAX_RESPONSE_BYTES = 1 << 20;  

    /** 
     * 原始 HTTP 发送
     * 端口存活探测,TCP connect 成功则认为端口开放
     */
    public static boolean checkPort(String host, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

     /**
     * 原始 Socket 发送 HTTP GET，返回响应文本
     * 路径不做编码,保留 ${jndi:..} 原样
     */
    public static String httpGet(String host, int port, String path, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            OutputStream out = s.getOutputStream();
            out.write(("GET " + path + " HTTP/1.1\r\n"
                    + "Host: " + host + ":" + port + "\r\n"
                    + "Connection: close\r\n\r\n").getBytes("UTF-8"));
            out.flush();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[8192];
            int n;
            while (buf.size() < MAX_RESPONSE_BYTES && (n = s.getInputStream().read(tmp)) > 0) {
                buf.write(tmp, 0, n);
            }
            return buf.toString("UTF-8");
        } catch (IOException e) {
            return "ERROR: " + e.getMessage();
        }
    }

    // 取状态行
    static String statusLine(String response) {
        int nl = response.indexOf("\r\n");
        return nl < 0 ? "?" : response.substring(0, nl);
    }

    public static void scan(String host, int port) {
        System.out.println("[*] Scanning " + host + ":" + port + " ...");

        if (!checkPort(host, port, 5000)) {
            System.out.println("[-] Port " + port + " is CLOSED or filtered");
            return;
        }
        System.out.println("[+] Port " + port + " is OPEN");

        String coresResp = httpGet(host, port, "/solr/admin/cores", 8000);
        System.out.println("[*] GET /solr/admin/cores -> " + statusLine(coresResp));
        Matcher m = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"").matcher(coresResp);
        while (m.find()) {
            System.out.println("[+] Solr core: " + m.group(1));
        }

        String sysResp = httpGet(host, port, "/solr/admin/info/system", 8000);
        System.out.println("[*] GET /solr/admin/info/system -> " + statusLine(sysResp));
        Matcher jvm = Pattern.compile("(1\\.8\\.0_\\d+|\\d+\\.\\d+[\\.\\d]*)\"").matcher(sysResp);
        String version = jvm.find() ? jvm.group(1) : "unknown";
        System.out.println("[+] JVM version: " + version);
        Matcher upd = Pattern.compile("1\\.8\\.0_(\\d+)").matcher(version);
        if (upd.find() && Integer.parseInt(upd.group(1)) < 191) {
            System.out.println("[+] VULNERABLE: JDK < 8u191, LDAP remote codebase loading allowed!");
        } else {
            System.out.println("[!] JDK >= 8u191: LDAP remote codebase loading blocked by default");
        }

        System.out.println("[*] Injection point: /solr/admin/cores?action=<value>"
                + "  (value is logged by Log4j)");
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: java EndpointScanner <host> [port]");
            System.exit(2);
        }
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 8983;
        scan(args[0], port);
    }
}
