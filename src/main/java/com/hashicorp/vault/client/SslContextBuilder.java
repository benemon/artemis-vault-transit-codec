package com.hashicorp.vault.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Builder for creating {@link SSLContext} instances for Vault TLS connections.
 *
 * <p>This class supports:
 * <ul>
 *   <li>Loading CA certificates from PEM files</li>
 *   <li>Loading client certificates and keys for mTLS</li>
 *   <li>Skip verification mode (trust all certificates)</li>
 * </ul>
 *
 * <p>Example usage:
 * <pre>{@code
 * SSLContext ctx = SslContextBuilder.create()
 *     .withCaCert("/path/to/ca.pem")
 *     .withClientCert("/path/to/cert.pem", "/path/to/key.pem")
 *     .build();
 * }</pre>
 */
public class SslContextBuilder {

    private static final Pattern PEM_CERT_PATTERN = Pattern.compile(
            "-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+/=\\s]+)\\s*-----END CERTIFICATE-----",
            Pattern.MULTILINE);

    private static final Pattern PEM_KEY_PATTERN = Pattern.compile(
            "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\\s*([A-Za-z0-9+/=\\s]+)\\s*-----END (?:RSA |EC )?PRIVATE KEY-----",
            Pattern.MULTILINE);

    private static final Pattern PKCS8_KEY_PATTERN = Pattern.compile(
            "-----BEGIN PRIVATE KEY-----\\s*([A-Za-z0-9+/=\\s]+)\\s*-----END PRIVATE KEY-----",
            Pattern.MULTILINE);

    private String caCertPath;
    private String clientCertPath;
    private String clientKeyPath;
    private boolean skipVerify;

    private SslContextBuilder() {
    }

    /**
     * Creates a new SSL context builder.
     *
     * @return a new builder instance
     */
    public static SslContextBuilder create() {
        return new SslContextBuilder();
    }

    /**
     * Sets the CA certificate path for server verification.
     *
     * @param path path to the CA certificate PEM file
     * @return this builder
     */
    public SslContextBuilder withCaCert(String path) {
        this.caCertPath = path;
        return this;
    }

    /**
     * Sets the client certificate and key paths for mTLS.
     *
     * @param certPath path to the client certificate PEM file
     * @param keyPath  path to the client private key PEM file
     * @return this builder
     */
    public SslContextBuilder withClientCert(String certPath, String keyPath) {
        this.clientCertPath = certPath;
        this.clientKeyPath = keyPath;
        return this;
    }

    /**
     * Enables skip verification mode (trust all certificates).
     *
     * <p><strong>Warning:</strong> This is insecure and should only be used
     * for development/testing.
     *
     * @param skip true to skip certificate verification
     * @return this builder
     */
    public SslContextBuilder withSkipVerify(boolean skip) {
        this.skipVerify = skip;
        return this;
    }

    /**
     * Builds the SSL context.
     *
     * @return the configured SSL context
     * @throws GeneralSecurityException if SSL configuration fails
     * @throws IOException              if certificate files cannot be read
     */
    public SSLContext build() throws GeneralSecurityException, IOException {
        SSLContext sslContext = SSLContext.getInstance("TLS");

        TrustManager[] trustManagers = createTrustManagers();
        KeyManager[] keyManagers = createKeyManagers();

        sslContext.init(keyManagers, trustManagers, new SecureRandom());
        return sslContext;
    }

    private TrustManager[] createTrustManagers() throws GeneralSecurityException, IOException {
        if (skipVerify) {
            return new TrustManager[]{createTrustAllManager()};
        }

        if (caCertPath == null) {
            // Use default trust store
            return null;
        }

        // Load CA cert into trust store
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        List<X509Certificate> certs = loadCertificates(caCertPath);
        for (int i = 0; i < certs.size(); i++) {
            trustStore.setCertificateEntry("ca-" + i, certs.get(i));
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        return tmf.getTrustManagers();
    }

    private KeyManager[] createKeyManagers() throws GeneralSecurityException, IOException {
        if (clientCertPath == null || clientKeyPath == null) {
            return null;
        }

        // Load client cert and key into key store
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        List<X509Certificate> certs = loadCertificates(clientCertPath);
        Certificate[] certChain = certs.toArray(new Certificate[0]);

        PrivateKey privateKey = loadPrivateKey(clientKeyPath);

        char[] keyPassword = new char[0]; // Empty password for in-memory key store
        keyStore.setKeyEntry("client", privateKey, keyPassword, certChain);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyPassword);
        return kmf.getKeyManagers();
    }

    private List<X509Certificate> loadCertificates(String path) throws IOException, GeneralSecurityException {
        String pem = Files.readString(Path.of(path), StandardCharsets.UTF_8);
        List<X509Certificate> certs = new ArrayList<>();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Matcher matcher = PEM_CERT_PATTERN.matcher(pem);

        while (matcher.find()) {
            String base64 = matcher.group(1).replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(der));
            certs.add(cert);
        }

        if (certs.isEmpty()) {
            throw new IllegalArgumentException("No certificates found in PEM file: " + path);
        }

        return certs;
    }

    private PrivateKey loadPrivateKey(String path) throws IOException, GeneralSecurityException {
        String pem = Files.readString(Path.of(path), StandardCharsets.UTF_8);

        // Try PKCS8 format first (-----BEGIN PRIVATE KEY-----)
        Matcher pkcs8Matcher = PKCS8_KEY_PATTERN.matcher(pem);
        if (pkcs8Matcher.find()) {
            String base64 = pkcs8Matcher.group(1).replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(der);

            // Try RSA first, then EC
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
            } catch (Exception e) {
                return KeyFactory.getInstance("EC").generatePrivate(keySpec);
            }
        }

        // Try traditional RSA/EC format (-----BEGIN RSA PRIVATE KEY-----)
        Matcher keyMatcher = PEM_KEY_PATTERN.matcher(pem);
        if (keyMatcher.find()) {
            // Traditional format needs conversion - this is complex
            // For simplicity, we require PKCS8 format or use OpenSSL to convert
            throw new IllegalArgumentException(
                    "Traditional PEM key format not supported. Please convert to PKCS8 format using: " +
                            "openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in " + path +
                            " -out " + path + ".pkcs8");
        }

        throw new IllegalArgumentException("No private key found in PEM file: " + path);
    }

    private X509TrustManager createTrustAllManager() {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // Trust all
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // Trust all
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }
}
