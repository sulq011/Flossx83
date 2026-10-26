package com.floss83.javaswitch.connection.connectiontests;

import com.floss83.javaswitch.connection.TcpServer;
import com.floss83.javaswitch.fraud.FraudClient;
import com.floss83.javaswitch.issuer.IssuerClient;
import com.floss83.javaswitch.tokenization.HsmSimulator;
import com.floss83.javaswitch.tokenization.TokenizationService;

/**
 * Standalone TCP switch (no Spring): tokenization + fraud + issuer.
 * Requires fraud engine on :8091 and issuer on :8092 to be running.
 */
public class ConnectionTestTcpServer {

    public static void main(String[] args) throws Exception {
        TokenizationService tokenizationService = new TokenizationService(new HsmSimulator());
        FraudClient fraudClient = new FraudClient("http://127.0.0.1:8091");
        IssuerClient issuerClient = new IssuerClient("http://127.0.0.1:8092", "");

        new Thread(new TcpServer(5000, tokenizationService, fraudClient, issuerClient)).start();

        while (true) {
            Thread.sleep(1000);
        }
    }
}
