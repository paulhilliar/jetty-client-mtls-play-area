package com.paulhilliar;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import nl.altindag.ssl.SSLFactory;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.Fields;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Optional;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

@Slf4j
@RequiredArgsConstructor
public class GeneratedCertsServer {

    private final CertificateUtils.GeneratedCert serverCert;
    private final X509ExtendedTrustManager frontendTrustManager;

    private Server server;

    public void start() throws Exception {
        server = new Server();

        SecureRequestCustomizer src = new SecureRequestCustomizer();    //makes the SSL session available in a request attribute
        src.setSniHostCheck(false);     //otherwise we get 400s due to localhost being rejected
        HttpConfiguration https = new HttpConfiguration();
        https.addCustomizer(src);

        val trustAnythingSslFactory = SSLFactory.builder()
            .withUnsafeTrustMaterial()
            .withUnsafeHostnameVerifier()
            .build();

        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server() {
            @Override
            protected TrustManager[] getTrustManagers(KeyStore trustStore, Collection<? extends CRL> crls) throws Exception {
                //if we return the frontend trust manager here then it will validate client certs at connection time, before we have the change to know the request URL
                //so we use the trustAnythingSslFactory
                //return new TrustManager[] {frontendTrustManager};

                //using trustAnythingSslFactory means we let any client connect, knowing that we will ensure a valid client cert later
                return new TrustManager[] { trustAnythingSslFactory.getTrustManager().get() };
            }
        };
        sslContextFactory.setNeedClientAuth(false);
        sslContextFactory.setWantClientAuth(true);      //need this otherwise we don't even check whether a client cert is presented

        //set up the cert that the server presents to clients
        PrivateKey privateKey = serverCert.getPrivateKey();
        char[] keyStorePassword = new char[0];
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, keyStorePassword);
        keyStore.setKeyEntry("server-key", privateKey, keyStorePassword, new Certificate[] {serverCert.getCertificate()});
        sslContextFactory.setKeyStore(keyStore);
        sslContextFactory.setKeyStorePassword(new String(keyStorePassword));

        ServerConnector connector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, "http/1.1"),
                new HttpConnectionFactory(https));
        connector.setPort(8443);

        server.setConnectors(new Connector[] {connector});
        server.setHandler(new HelloWorldHandler());

        server.start();
        log.info("Server is running at http://localhost:8443");
    }

    public void stop() throws Exception {
        server.stop();
    }

    private class HelloWorldHandler extends Handler.Abstract {
        @Override
        public boolean handle(Request request, Response response, Callback callback) throws Exception {

            if (isMtlsRequired(request) && !isClientCertificateValid(request)) {
                response.setStatus(401);
                response.getHeaders().put("WWW-Authenticate", "Mutual");
                response.write(true, ByteBuffer.wrap("Not Authenticated".getBytes()), callback);
                return true;
            }

            response.write(true, ByteBuffer.wrap("Successful call".getBytes()), callback);
            return true;
        }

        private boolean isClientCertificateValid(Request request) {
            X509Certificate[] clientCerts = null;
            try {
                val sslSessionData = (EndPoint.SslSessionData) request.getAttribute(EndPoint.SslSessionData.ATTRIBUTE);
                val sslSession = sslSessionData.sslSession();

                //getPeerCertificates gives us the client certificate chain that was negotiated when the connection was established.
                //It throws SSLPeerUnverifiedException if there was no client cert presented
                clientCerts = (X509Certificate[]) sslSession.getPeerCertificates();
            } catch (SSLPeerUnverifiedException e) {
                log.info("Client certificate is not present");
                return false;
            }

            try {
                log.info("Is client trusted?");
                String algorithm = clientCerts[0].getPublicKey().getAlgorithm();    //e.g. "RSA"
                frontendTrustManager.checkClientTrusted(clientCerts, algorithm);
                log.info("Client IS trusted :)");
                return true;
            } catch (CertificateException e) {
                log.error("Client is not trusted", e);
                return false;
            }
        }

        private static Boolean isMtlsRequired(Request request) {
            return Optional.ofNullable(Request.extractQueryParameters(request).get("requireMtls")).map(Fields.Field::getValue).map(Boolean::valueOf).orElse(true);
        }
    }

}
