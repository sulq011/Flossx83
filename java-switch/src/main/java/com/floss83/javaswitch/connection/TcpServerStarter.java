package com.floss83.javaswitch.connection;

import org.springframework.stereotype.Component;

import com.floss83.javaswitch.fraud.FraudClient;
import com.floss83.javaswitch.issuer.IssuerClient;
import com.floss83.javaswitch.tokenization.TokenizationService;

import jakarta.annotation.PostConstruct;

@Component
public class TcpServerStarter {

    private final TokenizationService tokenizationService;
    private final FraudClient fraudClient;
    private final IssuerClient issuerClient;

    public TcpServerStarter(TokenizationService tokenizationService,
                            FraudClient fraudClient,
                            IssuerClient issuerClient) {
        this.tokenizationService = tokenizationService;
        this.fraudClient = fraudClient;
        this.issuerClient = issuerClient;
    }

    @PostConstruct
    public void startTcpServer() {
        int port = 5000;
        Thread tcpThread = new Thread(
                new TcpServer(port, tokenizationService, fraudClient, issuerClient));
        tcpThread.setDaemon(true);
        tcpThread.start();
        System.out.println("[BOOT] TCP Server thread started on port " + port);
    }
}
