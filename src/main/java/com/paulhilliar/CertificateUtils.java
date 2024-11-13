package com.paulhilliar;

import static java.nio.charset.StandardCharsets.UTF_8;

import lombok.Value;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CertificateUtils {

    /**
     * Create a certificate
     * @param cnName The CN={name} of the certificate. When the certificate is for a domain it should be the domain name
     * @param domain Nullable. The DNS domain for the certificate.
     * @param issuer Issuer who signs this certificate. Null for a self-signed certificate
     * @param isCA   Can this certificate be used to sign other certificates
     * @return Newly created certificate with its private key
     */
    public static GeneratedCert createCertificate(String cnName, String domain, GeneratedCert issuer, boolean isCA) throws Exception {
        Map<String, Integer> sans = new HashMap<>();
        if (domain != null) {
            sans.put(domain, GeneralName.dNSName);
        }
        return createCertificate(cnName, issuer, sans, isCA ? CertType.CA : CertType.SERVER);
    }

    /**
     * Create a certificate
     * @param cnName The CN={name} of the certificate. When the certificate is for a domain it should be the domain name
     * @param issuer Issuer who signs this certificate. Null for a self-signed certificate
     * @param sans   Map of all Subject Alternative Names and their types to be added to the certificate extensions
     * @param certType Type of Certificate to be created CA, SERVER, CLIENT
     * @return Newly created certificate with its private key
     */
    public static GeneratedCert createCertificate(String cnName, GeneratedCert issuer, Map<String, Integer> sans, CertType certType) throws Exception {
        // Generate the key-pair with the official Java API's
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair certKeyPair = keyGen.generateKeyPair();
        X500Name name = new X500Name("CN=" + cnName);
        // If you issue more than just test certificates, you might want a decent serial number schema ^.^
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Instant validFrom = Instant.now();
        Instant validUntil = validFrom.plus(10 * 360, ChronoUnit.DAYS);

        // If there is no issuer, we self-sign our certificate.
        X500Name issuerName;
        PrivateKey issuerKey;
        if (issuer == null) {
            issuerName = name;
            issuerKey = certKeyPair.getPrivate();
        } else {
            issuerName = new X500Name(issuer.getCertificate().getSubjectDN().getName());
            issuerKey = issuer.getPrivateKey();
        }

        // The cert builder to build up our certificate information
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuerName,
            serialNumber,
            Date.from(validFrom), Date.from(validUntil),
            name, certKeyPair.getPublic());

        // Make the cert to a Cert Authority to sign more certs when needed
        switch (certType) {
            case CA:
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
                builder.addExtension(MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(NetscapeCertType.sslCA));
                break;
            case CLIENT:
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
                builder.addExtension(MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(NetscapeCertType.sslClient));
                builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
                break;
            case SERVER:
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
                builder.addExtension(MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(NetscapeCertType.sslServer));
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + certType);
        }
        // Populating the Subject Alternative Names
        if (sans != null && !sans.isEmpty()) {
            List<GeneralName> generalNameList = new ArrayList<>();
            for (Map.Entry<String, Integer> san : sans.entrySet()) {
                switch (san.getValue()) {
                    case GeneralName.rfc822Name:
                    case GeneralName.dNSName:
                    case GeneralName.uniformResourceIdentifier:
                    case GeneralName.directoryName:
                        generalNameList.add(new GeneralName(san.getValue(), san.getKey()));
                        break;
                    default:
                        throw new IllegalArgumentException("Not Supported SAN entry");
                }
            }
            builder.addExtension(Extension.subjectAlternativeName, true,
                new GeneralNames(generalNameList.toArray(new GeneralName[0])));
        }

        // Finally, sign the certificate:
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKey);
        X509CertificateHolder certHolder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

        return new GeneratedCert(certKeyPair.getPrivate(), cert);
    }


    public static String getCertificateString(Certificate certificate) throws CertificateEncodingException {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----\n");
        sb.append(new String(Base64.encode(certificate.getEncoded()), UTF_8));
        sb.append("\n-----END CERTIFICATE-----");
        return sb.toString();
    }


    public enum CertType {
        SERVER, CA, CLIENT;
    }

    @Value
    public static class GeneratedCert {
        PrivateKey privateKey;
        X509Certificate certificate;
    }
}
