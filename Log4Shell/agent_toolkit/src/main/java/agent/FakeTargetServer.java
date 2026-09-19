package agent;

import toolkit.LdapProbeClient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 模拟靶机（离线）：
 *
 *   1. 任何请求都回 400 Bad Request  --> 400 是正常现象；
 *   2. 若请求行里出现 ${jndi:ldap://...}，模拟"log4j 展开 lookup"：用真实 LDAP 客户端（LdapProbeClient）对 payload 里的 LDAP 地址做 bind+search+unbind 握手 
 *      —— 会真实触发 MaliciousLDAPServer 的searchHits 计数，因此 LLM 观察到的"回调命中是真实数出来的，不是测试伪造的。
 *
 * 实现必须用原始 ServerSocket 
 */
public class FakeTargetServer {

    private final ServerSocket server;
    private volatile boolean running = true;

    public final AtomicInteger requests = new AtomicInteger();
    public final AtomicInteger ldapCallbacks = new AtomicInteger();

    public FakeTargetServer(int port) throws IOException {
        server = new ServerSocket(port);
    }

    public void start() {
        Thread t = new Thread(() -> {
            while (running) {
                try {
                    Socket s = server.accept();
                    handle(s);
                } catch (IOException e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    public void stop() {
        running = false;
        try {
            server.close();
        } catch (IOException ignored) {
        }
    }

    private void handle(Socket s) {
        try (Socket c = s;
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(c.getInputStream(), StandardCharsets.ISO_8859_1));
             OutputStream out = c.getOutputStream()) {
            String line = in.readLine();
            if (line == null) {
                return;
            }
            requests.incrementAndGet();

            // 请求行: GET /path?query HTTP/1.1（query 保持原始字节，含 ${...}）
            int sp1 = line.indexOf(' ');
            int sp2 = line.indexOf(' ', sp1 + 1);
            String target = line.substring(sp1 + 1, sp2 < 0 ? line.length() : sp2);
            String query = target.contains("?") ? target.substring(target.indexOf('?') + 1) : null;

            while (true) {                 // 读请求头
                String h = in.readLine();
                if (h == null || h.isEmpty()) {
                    break;
                }
            }

            // 模拟 log4j lookup：payload 出现 jndi:ldap 就发起真实 LDAP 回调
            if (query != null && query.contains("${jndi:ldap://")) {
                String ldapTarget = LdapProbeClient.parseLdapTarget(query);
                if (ldapTarget != null) {
                    String[] hp = ldapTarget.split(":");
                    try {
                        boolean ok = LdapProbeClient.probe(
                                "127.0.0.1", Integer.parseInt(hp[1]), "cn=Exploit", 3000);
                        if (ok) {
                            ldapCallbacks.incrementAndGet();
                        }
                    } catch (Exception ignored) {
                    }
                }
            }

            byte[] body = "400 Bad Request (simulated Solr)".getBytes(StandardCharsets.ISO_8859_1);
            out.write(("HTTP/1.1 400 Bad Request\r\n"
                    + "Content-Length: " + body.length + "\r\n"
                    + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(body);
            out.flush();
        } catch (IOException ignored) {
        }
    }
}
