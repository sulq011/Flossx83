package com.floss83.javaswitch.fraud;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Fraud-engine client (v1.5).
 * Sends {mti, fields:{...}} to POST /score. Fields MUST contain tokens only
 * (PCI trust boundary: the fraud engine never sees raw PAN/CVV).
 *
 * v1.5 FIX: Spring's default JDK HttpClient attempts an HTTP/2 upgrade
 * ("Upgrade: h2c", "Connection: Upgrade, HTTP2-Settings") on the first
 * request, and uvicorn/h11 (FastAPI mode) DROPS the request body for
 * upgrade requests => FastAPI 422 "body missing". Forcing HTTP/1.1 in the
 * JDK HttpClient removes the upgrade headers entirely.
 *
 * FAIL-SAFE: engine unreachable => suspicious/review (never approve blind).
 */
@Component
public class FraudClient {

    public static final class FraudResult {
        public final String decision;
        public final int score;
        public final String recommendedAction;
        public final String triggeredRules;

        public FraudResult(String decision, int score, String recommendedAction, String triggeredRules) {
            this.decision = decision;
            this.score = score;
            this.recommendedAction = recommendedAction;
            this.triggeredRules = triggeredRules;
        }
    }

    private final RestClient restClient;
    private final ObjectMapper mapper = new ObjectMapper();

    public FraudClient(@Value("${fraud.engine.url:http://127.0.0.1:8091}") String fraudEngineUrl) {
        this.restClient = RestClient.builder()
                .baseUrl(fraudEngineUrl)
                .requestFactory(requestFactory())
                .build();
    }

    /** HTTP/1.1 ONLY (no h2c upgrade) + sane timeouts. */
    static JdkClientHttpRequestFactory requestFactory() {
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(Duration.ofSeconds(5));
        return factory;
    }

    public FraudResult score(String mti, Map<String, Object> fields) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("mti", mti == null ? "" : mti);
        payload.put("fields", fields == null ? new LinkedHashMap<String, Object>() : fields);
        try {
            String body = mapper.writeValueAsString(payload);
            System.out.println("[FRAUD-REQ] " + body);
            String response = restClient.post()
                    .uri("/score")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(String.class);
            System.out.println("[FRAUD-RES] " + response);
            JsonNode node = mapper.readTree(response);
            String rules = node.has("triggered_rules")
                    ? mapper.writeValueAsString(node.get("triggered_rules"))
                    : "[]";
            return new FraudResult(
                    node.path("decision").asText("suspicious"),
                    node.path("score").asInt(0),
                    node.path("recommended_action").asText("review"),
                    rules);
        } catch (Exception e) {
            System.err.println("[FRAUD] engine unreachable, fail-safe suspicious/review: " + e.getMessage());
            return new FraudResult("suspicious", 40, "review", "[]");
        }
    }
}
