package com.floss83.javaswitch.iso8583;

/**
 * ISO 8583 response builder (v1.6).
 * Bitmap 3038000006000000 = fields 3, 4, 11, 12, 13, 38, 39.
 *
 * v1.6: F2 is intentionally NOT echoed in responses. The token (44-char
 * base64) is not ISO-valid (F2 = n..19) and strict clients (iso8583sim)
 * reject the whole response because of it; the raw PAN must never leave
 * the switch (PCI). F2 is conditional in ISO responses, and clients match
 * responses by the echoed STAN (F11), so omitting it is safe.
 * The panToken parameter is kept for signature compatibility and ignored.
 *
 * v1.5: response MTI derived from request (0100->0110, 0200->0210);
 * STAN (F11) echoed for client-side response matching.
 */
public class Iso8583ResponseBuilder {

    private static final String RESPONSE_BITMAP = "3038000006000000";

    /** Derive the response MTI from the request MTI (0100->0110, 0200->0210). */
    public static String responseMti(String requestMti) {
        if (requestMti == null || requestMti.length() != 4) {
            return "0210";
        }
        char third = requestMti.charAt(2);
        return requestMti.substring(0, 2) + (third == '0' ? '1' : third) + requestMti.substring(3);
    }

    public static String buildResponse(String requestMti, String panToken, String field3,
                                       String field4, String field11, String field12,
                                       String field13, String authCode, String responseCode) {
        StringBuilder sb = new StringBuilder(96);
        sb.append(responseMti(requestMti));
        sb.append(RESPONSE_BITMAP);
        sb.append(pad(field3, 6));                             // F3 processing code
        sb.append(pad(field4, 12));                           // F4 amount
        sb.append(pad(field11, 6));                           // F11 STAN echo (client matching!)
        sb.append(pad(field12, 6));                           // F12 time
        sb.append(pad(field13, 4));                           // F13 date
        sb.append(pad(authCode, 6));                          // F38 approval code
        sb.append(pad(responseCode, 2));                      // F39 response code
        return sb.toString();
    }

    /** v1.4 compatibility (HTTP controller path): always 0210. */
    public static String build0210(String panToken, String field3, String field4,
                                   String field11, String field12, String field13,
                                   String authCode, String responseCode) {
        return buildResponse("0200", panToken, field3, field4, field11, field12,
                field13, authCode, responseCode);
    }

    /** Left-pad with '0' to exactly len chars (keep right-most if longer). */
    public static String pad(String value, int len) {
        String v = value == null ? "" : value;
        if (v.length() >= len) {
            return v.substring(v.length() - len);
        }
        StringBuilder sb = new StringBuilder(len);
        for (int i = v.length(); i < len; i++) {
            sb.append('0');
        }
        return sb.append(v).toString();
    }
}
