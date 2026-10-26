package com.floss83.javaswitch.connection;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import com.floss83.javaswitch.fraud.FraudClient;
import com.floss83.javaswitch.issuer.IssuerClient;
import com.floss83.javaswitch.iso8583.Iso8583Message;
import com.floss83.javaswitch.iso8583.Iso8583ParseException;
import com.floss83.javaswitch.iso8583.Iso8583Parser;
import com.floss83.javaswitch.iso8583.Iso8583ResponseBuilder;
import com.floss83.javaswitch.tokenization.TokenizationService;

/**
 * ISO 8583 TCP Server (v1.5).
 *
 * Wire protocol (compatible with iso8583sim --header 2b --format ascii-hex):
 *   frame = 2-byte BIG-ENDIAN binary length header + ASCII message.
 *
 * Concurrency: one thread per connection; per connection a MESSAGE LOOP
 * handles any number of framed messages (pipelining safe: client matches
 * responses by echoed STAN F11, so order flexibility is OK).
 *
 * Flow per message (unchanged from v1.4): parse -> capture RAW card data ->
 * tokenize (PCI) -> fraud score (tokens only) -> fraud gate -> issuer
 * authorize (raw, PAN owner) -> framed response with F38/F39.
 */
public class TcpServer implements Runnable {

    private final int port;
    private final TokenizationService tokenizationService;
    private final FraudClient fraudClient;
    private final IssuerClient issuerClient;

    public TcpServer(int port, TokenizationService tokenizationService,
                     FraudClient fraudClient, IssuerClient issuerClient) {
        this.port = port;
        this.tokenizationService = tokenizationService;
        this.fraudClient = fraudClient;
        this.issuerClient = issuerClient;
    }

    @Override
    public void run() {
        System.out.println("[TCP] Server starting on port " + port
                + " (framing: 2-byte binary length header, ascii-hex payload) ...");
        Iso8583Parser parser = new Iso8583Parser();

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[TCP] Connection from " + clientSocket.getRemoteSocketAddress());
                Thread worker = new Thread(() -> handleConnection(clientSocket, parser));
                worker.setDaemon(true);
                worker.start();
            }
        } catch (Exception e) {
            System.err.println("[TCP] Server exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /** Message loop for one connection: framed request -> framed response. */
    private void handleConnection(Socket socket, Iso8583Parser parser) {
        try (Socket s = socket;
             InputStream in = s.getInputStream();
             OutputStream out = s.getOutputStream()) {

            while (true) {
                byte[] header = readFully(in, 2);
                if (header == null) {                    // client closed connection
                    System.out.println("[TCP] Client closed connection");
                    return;
                }
                int length = ((header[0] & 0xFF) << 8) | (header[1] & 0xFF);
                if (length < 20 || length > 9999) {
                    System.out.println("[TCP] Invalid frame length " + length + " - closing connection");
                    return;
                }
                byte[] frame = readFully(in, length);
                if (frame == null) {
                    System.out.println("[TCP] Incomplete frame (expected " + length + ") - closing connection");
                    return;
                }
                String message = new String(frame, StandardCharsets.US_ASCII).trim();
                System.out.println("[TCP] Received (" + length + " chars): " + message);

                String response = processMessage(parser, message);
                writeFramed(out, response);
            }
        } catch (Exception e) {
            System.err.println("[TCP] Client handling error: " + e.getMessage());
        }
    }

    /** Full switch pipeline for one message; returns the response to frame back. */
    private String processMessage(Iso8583Parser parser, String message) {
        try {
            Iso8583Message parsed = parser.parse(message);

            // 1) RAW card data BEFORE tokenization (issuer only)
            String rawPan = parsed.getDataElement(2);
            String rawCvv = normalizeCvv(parsed.getDataElement(52));
            String rawExpiry = parsed.getDataElement(14);

            // 2) Tokenize PCI fields in place
            if (rawPan != null) {
                String panToken = tokenizationService.tokenizePan(rawPan);
                parsed.getMutableDataElements().put(2, panToken);
                System.out.println("[AUDIT] TOKENIZE_PAN       | IN: "
                        + tokenizationService.mask(rawPan)
                        + " -> OUT: " + tokenizationService.mask(panToken));
            }
            if (rawCvv != null) {
                String cvvToken = tokenizationService.tokenizeCvv(rawCvv);
                parsed.getMutableDataElements().put(52, cvvToken);
                System.out.println("[AUDIT] TOKENIZE_CVV       | IN: "
                        + tokenizationService.mask(rawCvv)
                        + " -> OUT: " + tokenizationService.mask(cvvToken));
            }

            System.out.println("[TCP] Parsed MTI: " + parsed.getMti());

            // 3) Fraud scoring - TOKENS ONLY
            Map<String, Object> fraudFields = new LinkedHashMap<>();
            parsed.getMutableDataElements().forEach((k, v) -> {
                if (v != null) {
                    fraudFields.put(String.valueOf(k), v);
                }
            });
            FraudClient.FraudResult fraud = fraudClient.score(parsed.getMti(), fraudFields);
            System.out.println("[FRAUD] decision=" + fraud.decision
                    + " score=" + fraud.score + " action=" + fraud.recommendedAction);

            String responseCode;
            String authCode;

            if ("fraud".equalsIgnoreCase(fraud.decision)) {
                // 4a) Fraud gate: hard decline, issuer never reached
                responseCode = "05";
                authCode = "000000";
                System.out.println("[ISSUER] skipped (fraud declined before issuer)");
            } else {
                // 4b) Issuer authorization with RAW card data (PAN owner)
                IssuerClient.IssuerResult issuer = issuerClient.authorize(
                        rawPan, rawCvv, rawExpiry,
                        parsed.getDataElement(4),
                        parsed.getMti(),
                        parsed.getDataElement(11));
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

            // 5) Response with REQUEST-DERIVED MTI (0100->0110) and STAN echo
            Map<Integer, String> f = parsed.getMutableDataElements();
            String isoResponse = Iso8583ResponseBuilder.buildResponse(
                    parsed.getMti(),
                    f.get(2), f.get(3), f.get(4), f.get(11), f.get(12), f.get(13),
                    authCode, responseCode);
            System.out.println("[TCP] Responding (ISO 8583 " + Iso8583ResponseBuilder.responseMti(parsed.getMti())
                    + ", F39=" + responseCode + " F38=" + authCode + "): " + isoResponse);
            return isoResponse;

        } catch (Iso8583ParseException ex) {
            System.err.println("[TCP] Parse Error: " + ex.getMessage());
            return "ERR: " + ex.getMessage();
        }
    }

    /** frame = 2-byte big-endian length + ASCII payload. */
    private static void writeFramed(OutputStream out, String text) throws IOException {
        byte[] payload = text.getBytes(StandardCharsets.US_ASCII);
        out.write((payload.length >> 8) & 0xFF);
        out.write(payload.length & 0xFF);
        out.write(payload);
        out.flush();
    }

    /** Read exactly n bytes; null on clean EOF before any byte. */
    private static byte[] readFully(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r == -1) {
                return null;
            }
            off += r;
        }
        return buf;
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
