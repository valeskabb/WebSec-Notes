package agent;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;

/**
 * LLM_BASE_URL    LLM 服务地址 ，默认为 http://localhost:11434/v1（Ollama）
 * LLM_API_KEY     密钥，默认 ollama
 * LLM_MODEL       模型名，默认 qwen2.5:7b 
 * LLM_TEMPERATURE 温度，默认为 0（值越小确定性越强）
 * ATTACKER_IP     攻击机地址
 */
public class AgentConfig {

    public final String baseUrl;
    public final String apiKey;
    public final String model;
    public final double temperature;
    public final String attackerIp;

    public AgentConfig() {
        this(null);
    }

    // 测试用固定的 attackerIp -- >127.0.0.1
    AgentConfig(String fixedAttackerIp) {
        baseUrl = env("LLM_BASE_URL", "http://localhost:11434/v1");
        apiKey = env("LLM_API_KEY", "ollama");
        model = env("LLM_MODEL", "qwen2.5:7b");
        temperature = Double.parseDouble(env("LLM_TEMPERATURE", "0"));
        attackerIp = fixedAttackerIp != null ? fixedAttackerIp : env("ATTACKER_IP", detectLocalIp());
    }

    private static String env(String key, String def) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? def : v;
    }

    /** 自动探测本机第一个非回环 IPv4（作为 LDAP codebase + 反弹 shell 的回调地址） */
    private static String detectLocalIp() {
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) {
                    continue;
                }
                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return "127.0.0.1";
    }
}
