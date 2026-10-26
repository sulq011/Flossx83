package com.floss83.javaswitch.connection;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.floss83.javaswitch.fraud.FraudClient;
import com.floss83.javaswitch.issuer.IssuerClient;
import com.floss83.javaswitch.iso8583.Iso8583Message;
import com.floss83.javaswitch.iso8583.Iso8583ParseException;
import com.floss83.javaswitch.iso8583.Iso8583Parser;
import com.floss83.javaswitch.iso8583.Iso8583ResponseBuilder;
import com.floss83.javaswitch.tokenization.TokenizationService;

/**
 * HTTP entry point (v1.4): parse -> tokenize at the door (PCI) ->
 * fraud score (tokens only) -> fraud gate -> issuer authorize (raw) ->
 * JSON with mti/fields/fraud/issuer/response_code/auth_code/iso8583_response.
 */
@RestController
@RequestMapping("/api/iso8583")
public class IsoMessageController {

    private static final int FIELD_PAN = 2;
    private static final int FIELD_CVV = 52;
    private static final int FIELD_EXPIRY = 14;

    private final Iso8583Parser parser = new Iso8583Parser();
    private final TokenizationService tokenizationService;
    private final FraudClient fraudClient;
    private final IssuerClient issuerClient;

    public IsoMessageController(TokenizationService tokenizationService,
                                FraudClient fraudClient,
                                IssuerClient issuerClient) {
        this.tokenizationService = tokenizationService;
        this.fraudClient = fraudClient;
        this.issuerClient = issuerClient;
    }

    @PostMapping(produces = "application/json")
    public ResponseEntity<?> receiveIsoMessage(@RequestBody String isoMessage) {
        System.out.println("[HTTP] Received: " + isoMessage);

        try {
            Iso8583Message parsed = parser.parse(isoMessage);
            Map<Integer, String> fields = new TreeMap<>(parsed.getMutableDataElements());

            // 1) RAW card data BEFORE tokenization (issuer only)
            String rawPan = fields.get(FIELD_PAN);
            String rawCvv = normalizeCvv(fields.get(FIELD_CVV));
            String rawExpiry = fields.get(FIELD_EXPIRY);

            // 2) Tokenize PAN/CVV - downstream sees tokens only
            String panToken = null;
            String cvvToken = null;
            if (rawPan != null) {
                panToken = tokenizationService.tokenizePan(rawPan);
                System.out.println("[AUDIT] TOKENIZE_PAN       | IN: "
                        + tokenizationService.mask(rawPan)
                        + " -> OUT: " + tokenizationService.mask(panToken));
            }
            if (rawCvv != null) {
                cvvToken = tokenizationService.tokenizeCvv(rawCvv);
                System.out.println("[AUDIT] TOKENIZE_CVV       | IN: "
                        + tokenizationService.mask(rawCvv)
                        + " -> OUT: " + tokenizationService.mask(cvvToken));
            }

            // 3) Output fields (tokens only)
            Map<String, Object> outputFields = new LinkedHashMap<>();
            if (panToken != null) {
                outputFields.put("2_PAN_tokenized", panToken);
            }
            if (cvvToken != null) {
                outputFields.put("52_CVV_tokenized", cvvToken);
            }
            for (Map.Entry<Integer, String> e : fields.entrySet()) {
                if (e.getKey() == FIELD_PAN || e.getKey() == FIELD_CVV) {
                    continue;
                }
                outputFields.put(String.valueOf(e.getKey()), e.getValue());
            }

            System.out.println("[HTTP] Parsed MTI: " + parsed.getMti());
            outputFields.forEach((k, v) -> System.out.println("[HTTP] Field " + k + ": " + v));

            // 4) Fraud scoring - TOKENS ONLY (copy of map, never raw)
            Map<String, Object> fraudFields = new LinkedHashMap<>();
            for (Map.Entry<Integer, String> e : fields.entrySet()) {
                if (e.getKey() == FIELD_PAN || e.getKey() == FIELD_CVV) {
                    continue;
                }
                if (e.getValue() != null) {
                    fraudFields.put(String.valueOf(e.getKey()), e.getValue());
                }
            }
            if (panToken != null) {
                fraudFields.put("2", panToken);
            }
            if (cvvToken != null) {
                fraudFields.put("52", cvvToken);
            }
            FraudClient.FraudResult fraud = fraudClient.score(parsed.getMti(), fraudFields);
            System.out.println("[FRAUD] decision=" + fraud.decision
                    + " score=" + fraud.score + " action=" + fraud.recommendedAction);

            Map<String, Object> fraudBlock = new LinkedHashMap<>();
            fraudBlock.put("decision", fraud.decision);
            fraudBlock.put("score", fraud.score);
            fraudBlock.put("recommended_action", fraud.recommendedAction);
            fraudBlock.put("triggered_rules", fraud.triggeredRules);

            // 5) Fraud gate -> issuer
            String responseCode;
            String authCode;
            Map<String, Object> issuerBlock = new LinkedHashMap<>();

            if ("fraud".equalsIgnoreCase(fraud.decision)) {
                responseCode = "05";
                authCode = "000000";
                issuerBlock.put("skipped", true);
                issuerBlock.put("reason", "declined by fraud before issuer");
                System.out.println("[ISSUER] skipped (fraud declined before issuer)");
            } else {
                IssuerClient.IssuerResult issuer = issuerClient.authorize(
                        rawPan, rawCvv, rawExpiry,
                        fields.get(4), parsed.getMti(), fields.get(11));
                issuerBlock.put("approved", issuer.approved);
                issuerBlock.put("response_code", issuer.responseCode);
                issuerBlock.put("auth_code", issuer.authCode);
                issuerBlock.put("reason", issuer.reason);
                System.out.println("[ISSUER] approved=" + issuer.approved
                        + " rc=" + issuer.responseCode
                        + " auth=" + issuer.authCode
                        + " reason=" + issuer.reason);

                if (!issuer.approved) {
                    responseCode = issuer.responseCode;
                    authCode = "000000";
                } else if ("suspicious".equalsIgnoreCase(fraud.decision)) {
                    responseCode = "01";
                    authCode = issuer.authCode;
                } else {
                    responseCode = "00";
                    authCode = issuer.authCode;
                }
            }

            // 6) ISO 8583 0210 (F2 = TOKEN echo)
            String panEcho = panToken != null ? panToken : fields.get(FIELD_PAN);
            String iso0210 = Iso8583ResponseBuilder.build0210(
                    panEcho, fields.get(3), fields.get(4), fields.get(11),
                    fields.get(12), fields.get(13), authCode, responseCode);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("mti", parsed.getMti());
            result.put("fields", outputFields);
            result.put("fraud", fraudBlock);
            result.put("issuer", issuerBlock);
            result.put("response_code", responseCode);
            result.put("auth_code", authCode);
            result.put("iso8583_response", iso0210);
            return ResponseEntity.ok(result);

        } catch (Iso8583ParseException ex) {
            System.err.println("[HTTP] Parse Error: " + ex.getMessage());
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Parse error: " + ex.getMessage()));
        }
    }

    /** F52 arrives fixed-length 16 padded (0/F/space); issuer wants the real CVV. */
    private static String normalizeCvv(String cvv) {
        if (cvv == null) {
            return null;
        }
        String v = cvv.trim();
        if (v.length() <= 4) {
            return v;
        }
        String stripped = v.replaceAll("[0Ff]+$", "");
        return stripped.length() >= 3 ? stripped : v;
    }
}
