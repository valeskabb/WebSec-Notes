package toolkit;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 简易LDAP客户端
 *
 * 走的是真实的 TCP + BER 编码，因此能触发真正的 MaliciousLDAPServer 的 searchHits 计数 ，计数是真实的
 */
public class LdapProbeClient {

    // 从 payload 里解析 LDAP 服务器地址：jndi:ldap://HOST:PORT/...
    public static String parseLdapTarget(String payload) {
        Matcher m = Pattern.compile("ldap://([^/}]+)").matcher(payload);
        return m.find() ? m.group(1) : null;
    }

    public static boolean probe(String host, int port, String baseDn, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            int msgId = 1;

            out.write(bind(msgId++));
            out.flush();
            byte[] bindResp = readLdapMessage(in);

            out.write(search(msgId++, baseDn));
            out.flush();
            byte[] entry = readLdapMessage(in);
            readLdapMessage(in);      // SearchResultDone

            out.write(unbind(msgId++));
            out.flush();

            return contains(entry, "javaNamingReference");
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean contains(byte[] msg, String s) {
        return msg != null && new String(msg).contains(s);
    }

    // 构造 BER

    private static byte[] bind(int id) {
        // BindRequest: 0x60 
        return ldapMessage(id, new byte[]{
                (byte) 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, (byte) 0x80, 0x00});
    }

    private static byte[] search(int id, String baseDn) {
        // SearchRequest: 0x63 
        byte[] dn = octet(baseDn);
        // 按 LDAP 协议规范，依次拼接 SearchRequest 的各个字段
        byte[] inner = concat(dn,
                new byte[]{(byte) 0x0A, 0x01, 0x00},   
                new byte[]{(byte) 0x0A, 0x01, 0x00},   
                new byte[]{(byte) 0x02, 0x01, 0x00},   
                new byte[]{(byte) 0x02, 0x01, 0x00},  
                new byte[]{0x01, 0x01, 0x00},         
                new byte[]{(byte) 0xA3, 0x05, (byte) 0x87, 0x03, 0x01, 0x01, 0x00}, 
                new byte[]{(byte) 0x30, 0x00});       
        return ldapMessage(id, tlv(0x63, inner));
    }

    private static byte[] unbind(int id) {
        return ldapMessage(id, new byte[]{(byte) 0x42, 0x00});
    }

    private static byte[] ldapMessage(int id, byte[] op) {
        return tlv(0x30, concat(new byte[]{0x02, 0x01, (byte) id}, op));
    }

    private static byte[] octet(String s) {
        byte[] b = s.getBytes();
        return tlv(0x04, b);
    }

    private static byte[] tlv(int tag, byte[] content) {
        byte[] out = new byte[1 + content.length + (content.length < 128 ? 1 : 2)];
        int p = 0;
        out[p++] = (byte) tag;
        if (content.length < 128) {
            out[p++] = (byte) content.length;
        } else {
            out[p++] = (byte) 0x81;
            out[p++] = (byte) content.length;
        }
        System.arraycopy(content, 0, out, p, content.length);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.write(p, 0, p.length);
        }
        return out.toByteArray();
    }

    /** 读一条 LDAPMessage（含头部） */
    static byte[] readLdapMessage(InputStream in) throws Exception {
        int tag = in.read();
        int first = in.read();
        if (first < 0) {
            return null;
        }
        int len = first;
        if ((first & 0x80) != 0) {
            int nb = first & 0x7F;
            len = 0;
            for (int i = 0; i < nb; i++) {
                len = (len << 8) | in.read();
            }
        }
        byte[] body = new byte[len];
        int off = 0;
        while (off < len) {
            int n = in.read(body, off, len - off);
            if (n < 0) {
                break;
            }
            off += n;
        }
        byte[] msg = new byte[2 + (len < 128 ? 0 : 1) + len];
        msg[0] = (byte) tag;
        msg[1] = (byte) (len < 128 ? len : 0x81);
        if (len >= 128) {
            msg[2] = (byte) len;
        }
        System.arraycopy(body, 0, msg, 2 + (len < 128 ? 0 : 1), len);
        return msg;
    }
}
