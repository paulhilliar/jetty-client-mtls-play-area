package com.paulhilliar;

import static com.paulhilliar.CertificateUtils.CertType.CA;
import static com.paulhilliar.CertificateUtils.CertType.CLIENT;
import static com.paulhilliar.CertificateUtils.createCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.paulhilliar.CertificateUtils.GeneratedCert;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.jetty.util.JettySslUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLHandshakeException;

/**
 * This is an example of how to use the Jetty client to pass client certificate chains with a request.
 *
 * When the client passes a certificate chain (not just a single certificate) then the server doesn't have to have the client cert issuer CA in its trust store.
 *
 * Instead, the server just needs to match up something in its trust store with something in the issuer chain provided by the client.
 */
@Slf4j
public class ClientCertificateChainLengthTest {

    static final String CLIENT_NAME = "client.com";
    static final String SERVER_NAME = "server.com";

    static CertificateLengthServer server;
    static GeneratedCert serverCa;
    static GeneratedCert serverCert;

    static GeneratedCert clientRootCA;
    static GeneratedCert intermediateCA1;
    static GeneratedCert intermediateCA2;
    static GeneratedCert intermediateCA3;
    static GeneratedCert clientCertSignedByCA2;
    static GeneratedCert clientCertSignedByCA3;

    @BeforeAll
    static void setUp() throws Exception {
        System.setProperty("jdk.tls.maxCertificateChainLength", "3");

        serverCa = createCertificate("ServerCA", null, null, CA);
        serverCert = createCertificate(SERVER_NAME, SERVER_NAME, serverCa, false);


        clientRootCA = createCertificate("clientRootCA", null, null, CA);
        intermediateCA1 = createCertificate("intermediateCA1", clientRootCA, null, CA);
        intermediateCA2 = createCertificate("intermediateCA2", intermediateCA1, null, CA);
        intermediateCA3 = createCertificate("intermediateCA3", intermediateCA2, null, CA);

        clientCertSignedByCA2 = createCertificate(CLIENT_NAME, intermediateCA2, Map.of(), CLIENT);
        clientCertSignedByCA3 = createCertificate(CLIENT_NAME, intermediateCA3, Map.of(), CLIENT);

        //the server only has clientRootCA in its frontend trust store
        //the other (intermediate1 + intermediate2 + clientCert) come in the request
        val serverSideSslFactory = SSLFactory.builder().withTrustMaterial(List.of(clientRootCA.getCertificate())).build();
        server = new CertificateLengthServer(serverCert, serverSideSslFactory.getTrustManager().get());
        server.start();
    }

    @AfterAll
    static void stopServer() throws Exception {
        if (server != null) {
            server.stop();
        }
    }


    @Test
    void testChainLengthValidation() throws Exception {
        try (val httpClient = buildMtlsClient(clientCertSignedByCA2, new GeneratedCert[] {clientCertSignedByCA2, intermediateCA2, intermediateCA1})) {
            assertThat(httpClient.newRequest("https://localhost:8443?maxChainLength=3").send().getStatus()).isEqualTo(200);

            //chain length validation should fail
            assertThat(httpClient.newRequest("https://localhost:8443?maxChainLength=2").send().getStatus()).isEqualTo(401);
        }
    }

    @Test
    void testChainLengthFourRejectedByJDK() throws Exception {
        try (val httpClient = buildMtlsClient(clientCertSignedByCA3, new GeneratedCert[]{clientCertSignedByCA3, intermediateCA3, intermediateCA2, intermediateCA1})) {
            //JDK should step in and reject
            //see jdk.tls.maxCertificateChainLength
            //https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-A41282C3-19A3-400A-A40F-86F4DA22ABA9
            assertThatThrownBy(() -> httpClient.newRequest("https://localhost:8443?maxChainLength=3").send().getStatus())
                .hasRootCauseExactlyInstanceOf(SSLHandshakeException.class)
                .hasRootCauseMessage("Received fatal alert: handshake_failure")
                .satisfies(e -> log.info("Captured exception", e));
        }
    }


    HttpClient buildMtlsClient(GeneratedCert clientCert, GeneratedCert[] certificateChain) throws Exception {
        val httpClient = new HttpClient();
        X509Certificate[] chain = Arrays.stream(certificateChain).map(GeneratedCert::getCertificate).toList().toArray(new X509Certificate[0]);
        httpClient.setSslContextFactory(createClientSideSslSocketFactory(clientCert.getPrivateKey(), chain));
        httpClient.start();
        return httpClient;
    }

    static SslContextFactory.Client createClientSideSslSocketFactory(PrivateKey privateKey, X509Certificate[] certificateChain) throws Exception {
        char[] privateKeyPassword = new char[0];

        SSLFactory.Builder sslBuilder = SSLFactory.builder()
            .withIdentityMaterial(privateKey, privateKeyPassword, certificateChain)
            .withUnsafeHostnameVerifier()   //we can't verify localhost anyway, and we don't care about client-side validation here
            .withUnsafeTrustMaterial();     //otherwise we get SSLHandshakeException: No subject alternative DNS name matching localhost found.

        return JettySslUtils.forClient(sslBuilder.build());
    }

}