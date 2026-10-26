package com.floss83.javaswitch.issuer;

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
 * Issuer client (v1.5) - acquirer -> issuer relay.
 * The ONLY component allowed to carry RAW card data (PAN/CVV),
 * because the issuer is the PAN owner.
 *
 * v1.5 FIX: force HTTP/1.1 in the JDK HttpClient (Spring's default
 * sends "Upgrade: h2c" which makes uvicorn/h11 drop the request body).
 * CRITICAL for the future: the real card-service on sull.world will be
 * FastAPI/uvicorn and would hit exactly the same 422 bug without this.
 *
 * FAIL-SAFE: issuer unreachable => decline 91 (never approve blind).
 */
@Component
public class IssuerClient {

    public static final class IssuerResult {
        public final boolean approved;
        public final String responseCode;
        public final String authCode;
        public final String reason;

        public IssuerResult(boolean approved, String responseCode, String authCode, String reason) {
            this.approved = approved;
            this.responseCode = responseCode;
            this.authCode = authCode;
            this.reason = reason;
        }
    }

    private final RestClient restClient;
    private final ObjectMapper mapper = new ObjectMapper();
    private final String apiKey;

    public IssuerClient(@Value("${issuer.url:http://127.0.0.1:8092}") String issuerUrl,
                        @Value("${issuer.api-key:}") String apiKey) {
        this.restClient = RestClient.builder()
                .baseUrl(issuerUrl)
                .requestFactory(requestFactory())
                .build();
        this.apiKey = apiKey;
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

    public IssuerResult authorize(String pan, String cvv, String expiry, String amountMinor,
                                   String mti, String stan) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("pan", pan == null ? "" : pan);
        payload.put("cvv", cvv == null ? "" : cvv);
        payload.put("expiry", expiry == null ? "" : expiry);
        payload.put("amount", parseAmount(amountMinor)); // minor units as JSON number
        payload.put("mti", mti == null ? "" : mti);
        payload.put("stan", stan == null ? "" : stan);
        try {
            String body = mapper.writeValueAsString(payload);
            System.out.println("[ISSUER-REQ] " + body);
            RestClient.RequestBodySpec spec = restClient.post()
                    .uri("/switch/authorize")
                    .contentType(MediaType.APPLICATION_JSON);
            if (apiKey != null && !apiKey.isBlank()) {
                spec = spec.header("X-API-Key", apiKey);
            }
            String response = spec.body(body).retrieve().body(String.class);
            System.out.println("[ISSUER-RES] " + response);
            JsonNode node = mapper.readTree(response);
            return new IssuerResult(
                    node.path("approved").asBoolean(false),
                    node.path("response_code").asText("91"),
                    node.path("auth_code").asText("000000"),
                    node.path("reason").asText(""));
        } catch (Exception e) {
            System.err.println("[ISSUER] unavailable, fail-safe 91: " + e.getMessage());
            return new IssuerResult(false, "91", "000000", "issuer unavailable");
        }
    }

    private static long parseAmount(String f4) {
        try {
            return (f4 == null || f4.isBlank()) ? 0L : Long.parseLong(f4.trim());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }
}
