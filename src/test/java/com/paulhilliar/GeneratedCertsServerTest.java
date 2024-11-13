package com.paulhilliar;

import static com.paulhilliar.CertificateUtils.CertType.CA;
import static com.paulhilliar.CertificateUtils.CertType.CLIENT;
import static com.paulhilliar.CertificateUtils.createCertificate;
import static com.paulhilliar.CertificateUtils.getCertificateString;
import static org.assertj.core.api.Assertions.assertThat;

import com.paulhilliar.CertificateUtils.GeneratedCert;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.jetty.util.JettySslUtils;
import nl.altindag.ssl.pem.util.PemUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.util.Map;
import javax.net.ssl.X509ExtendedTrustManager;

@Slf4j
public class GeneratedCertsServerTest {

    static final String CLIENT_NAME = "client.com";
    static final String SERVER_NAME = "server.com";

    static GeneratedCertsServer server;
    static GeneratedCert serverCa;
    static GeneratedCert serverCert;
    static GeneratedCert clientCa;
    static GeneratedCert trustedClientCert;
    static GeneratedCert notTrustedCaCert;
    static GeneratedCert notTrustedClientCert;
    HttpClient httpClient;

    @BeforeAll
    static void setUp() throws Exception {
        serverCa = createCertificate("ServerCA", null, null, CA);
        serverCert = createCertificate(SERVER_NAME, SERVER_NAME, serverCa, false);

        clientCa = createCertificate("ClientCA", null, null, CA);
        trustedClientCert = createCertificate(CLIENT_NAME, clientCa, Map.of(), CLIENT);

        notTrustedCaCert = createCertificate("NotTrustedCA", null, null, CA);
        notTrustedClientCert = createCertificate(CLIENT_NAME, notTrustedCaCert, Map.of(), CLIENT);

        String frontendCaPem = getCertificateString(clientCa.getCertificate());
        val bais = new ByteArrayInputStream(frontendCaPem.getBytes());
        X509ExtendedTrustManager frontendTrustManager = PemUtils.loadTrustMaterial(bais);

        server = new GeneratedCertsServer(serverCert, frontendTrustManager);
        server.start();
    }

    @AfterAll
    static void stopServer() throws Exception {
        if (server != null) {
            server.stop();
        }
    }

    @AfterEach
    void stopClient() throws Exception {
        if (httpClient != null) {
            httpClient.stop();
        }
    }

    @Test
    void trustedCertificate() throws Exception {
        buildMtlsClient(trustedClientCert);

        //valid client cert is presented
        assertThat(httpClient.newRequest("https://localhost:8443?requireMtls=true").send().getStatus()).isEqualTo(200);

        //valid client cert is presented but is never programmatically validated due to requireMtls=false
        assertThat(httpClient.newRequest("https://localhost:8443?requireMtls=false").send().getStatus()).isEqualTo(200);
    }

    @Test
    void noCertificate() throws Exception {
        buildMtlsClient(null);

        //lack of client cert means this will be rejected
        assertThat(httpClient.newRequest("https://localhost:8443?requireMtls=true").send().getStatus()).isEqualTo(401);

        //because the client cert is not checked (requireMtls=false) and sslContextFactory.setNeedClientAuth is false
        //then the lack of client cert is never uncovered
        assertThat(httpClient.newRequest("https://localhost:8443?requireMtls=false").send().getStatus()).isEqualTo(200);
    }

    @Test
    void untrustedCertificate() throws Exception {
        buildMtlsClient(notTrustedClientCert);

        //client cert is not trusted - will be rejected
        assertThat(httpClient.newRequest("https://localhost:8443?requireMtls=true").send().getStatus()).isEqualTo(401);

        //client cert is not validated (requireMtls=false) and therefore will be accepted
        assertThat(httpClient.newRequest("https://localhost:8443?requireMtls=false").send().getStatus()).isEqualTo(200);
    }

    HttpClient buildMtlsClient(GeneratedCert useClientCert) throws Exception {
        httpClient = new HttpClient();
        httpClient.setSslContextFactory(createSslSocketFactory(useClientCert));
        httpClient.start();
        return httpClient;
    }

    static SslContextFactory.Client createSslSocketFactory(GeneratedCert clientCert) throws Exception {
        SSLFactory.Builder sslBuilder = SSLFactory.builder()
            .withUnsafeHostnameVerifier()   //we can't verify localhost anyway and we don't care about client-side validation here
            .withUnsafeTrustMaterial();     //otherwise we get SSLHandshakeException: No subject alternative DNS name matching localhost found.

        if (clientCert != null) {
            char[] keyStorePassword = new char[0];
            KeyStore identityStore = KeyStoreUtils.createIdentityStore(clientCert.getPrivateKey(), keyStorePassword, clientCert.getCertificate());
            sslBuilder.withIdentityMaterial(identityStore, keyStorePassword);
        }

        return JettySslUtils.forClient(sslBuilder.build());
    }

}