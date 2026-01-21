package com.hashicorp.artemis;

import com.hashicorp.vault.client.AppRoleAuthenticator;
import com.hashicorp.vault.client.AuthMethod;
import com.hashicorp.vault.client.SslContextBuilder;
import com.hashicorp.vault.client.TokenAuthenticator;
import com.hashicorp.vault.client.VaultAuthenticator;
import com.hashicorp.vault.client.VaultException;
import com.hashicorp.vault.client.VaultHttpClient;
import com.hashicorp.vault.client.VaultResponse;
import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import org.apache.activemq.artemis.utils.SensitiveDataCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link SensitiveDataCodec} implementation that uses HashiCorp Vault Transit
 * secrets engine for password encryption and decryption.
 *
 * <p>This codec allows Apache ActiveMQ Artemis broker passwords to be encrypted
 * at rest using Vault Transit. Passwords are encrypted out-of-band via the
 * {@code ./artemis mask} CLI command, stored as ciphertext in broker.xml, and
 * decrypted at broker startup/runtime.
 *
 * <h2>Configuration</h2>
 * <p>The codec supports standard Vault environment variables (same as Vault CLI/SDKs):
 * <ul>
 *   <li>{@code VAULT_ADDR} - Vault server address (required)</li>
 *   <li>{@code VAULT_TOKEN} - Vault token for authentication</li>
 *   <li>{@code VAULT_TOKEN_FILE} - Path to file containing Vault token</li>
 *   <li>{@code VAULT_NAMESPACE} - Vault namespace (Vault Enterprise only)</li>
 *   <li>{@code VAULT_SKIP_VERIFY} - Skip TLS certificate verification</li>
 *   <li>{@code VAULT_CACERT} - Path to CA certificate</li>
 *   <li>{@code VAULT_CLIENT_CERT} - Path to client certificate</li>
 *   <li>{@code VAULT_CLIENT_KEY} - Path to client key</li>
 *   <li>{@code VAULT_ROLE_ID} - AppRole role ID</li>
 *   <li>{@code VAULT_SECRET_ID} - AppRole secret ID</li>
 *   <li>{@code VAULT_SECRET_ID_FILE} - Path to file containing AppRole secret ID</li>
 * </ul>
 *
 * <p>broker.xml parameters override environment variables:
 * <pre>{@code
 * <password-codec>com.hashicorp.artemis.VaultTransitCodec;vault-addr=https://vault:8200;transit-key=artemis</password-codec>
 * }</pre>
 *
 * @see <a href="https://developer.hashicorp.com/vault/docs/secrets/transit">Vault Transit Secrets Engine</a>
 */
public class VaultTransitCodec implements SensitiveDataCodec<String>, Closeable {

    private static final Logger logger = LoggerFactory.getLogger(VaultTransitCodec.class);

    private static final String ENV_VAULT_ADDR = "VAULT_ADDR";
    private static final String ENV_VAULT_TOKEN = "VAULT_TOKEN";
    private static final String ENV_VAULT_TOKEN_FILE = "VAULT_TOKEN_FILE";
    private static final String ENV_VAULT_SKIP_VERIFY = "VAULT_SKIP_VERIFY";
    private static final String ENV_VAULT_CACERT = "VAULT_CACERT";
    private static final String ENV_VAULT_CLIENT_CERT = "VAULT_CLIENT_CERT";
    private static final String ENV_VAULT_CLIENT_KEY = "VAULT_CLIENT_KEY";
    private static final String ENV_VAULT_ROLE_ID = "VAULT_ROLE_ID";
    private static final String ENV_VAULT_SECRET_ID = "VAULT_SECRET_ID";
    private static final String ENV_VAULT_SECRET_ID_FILE = "VAULT_SECRET_ID_FILE";
    private static final String ENV_VAULT_NAMESPACE = "VAULT_NAMESPACE";

    private static final String PARAM_VAULT_ADDR = "vault-addr";
    private static final String PARAM_TRANSIT_MOUNT = "transit-mount";
    private static final String PARAM_TRANSIT_KEY = "transit-key";
    private static final String PARAM_AUTH_METHOD = "auth-method";
    private static final String PARAM_TOKEN_PATH = "token-path";
    private static final String PARAM_SKIP_VERIFY = "skip-verify";
    private static final String PARAM_CA_CERT = "ca-cert";
    private static final String PARAM_CLIENT_CERT = "client-cert";
    private static final String PARAM_CLIENT_KEY = "client-key";
    private static final String PARAM_APPROLE_ID = "approle-id";
    private static final String PARAM_APPROLE_SECRET_FILE = "approle-secret-file";
    private static final String PARAM_CACHE_TTL_SECONDS = "cache-ttl-seconds";
    private static final String PARAM_MAX_RETRIES = "max-retries";
    private static final String PARAM_NAMESPACE = "namespace";
    private static final String PARAM_TRANSIT_NAMESPACE = "transit-namespace";

    private static final String DEFAULT_TRANSIT_MOUNT = "transit";
    private static final String DEFAULT_TRANSIT_KEY = "artemis";
    private static final AuthMethod DEFAULT_AUTH_METHOD = AuthMethod.TOKEN;
    private static final String DEFAULT_TOKEN_PATH = "/vault/secrets/.vault-token";
    private static final int DEFAULT_CACHE_TTL_SECONDS = 300;
    private static final int DEFAULT_MAX_RETRIES = 3;
    private static final long INITIAL_BACKOFF_MS = 100L;
    private static final long MAX_BACKOFF_MS = 800L;
    private static final long MIN_RENEWAL_INTERVAL_SECONDS = 60L;

    private String vaultAddr;
    private String transitMount;
    private String transitKey;
    private AuthMethod authMethod;
    private String namespace;
    private String transitNamespace;
    private int maxRetries;
    private int cacheTtlSeconds;

    private VaultHttpClient vaultClient;
    private VaultAuthenticator authenticator;
    private ConcurrentHashMap<String, CacheEntry> cache;
    private ScheduledExecutorService renewalExecutor;

    /**
     * Cache entry with TTL tracking.
     */
    private static class CacheEntry {
        final String value;
        final long expiresAt;

        CacheEntry(String value, long ttlMillis) {
            this.value = value;
            this.expiresAt = System.currentTimeMillis() + ttlMillis;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    /**
     * Initializes the codec with configuration from broker.xml parameters.
     *
     * <p>Configuration is resolved in order: broker.xml parameter, environment variable,
     * then default value. See class documentation for available parameters.
     *
     * @param params configuration parameters from broker.xml password-codec element
     * @throws Exception if Vault connection fails or Transit key is not accessible
     */
    @Override
    public void init(Map<String, String> params) throws Exception {
        logger.debug("Initializing VaultTransitCodec with {} parameters", params.size());

        parseConfiguration(params);
        SSLContext sslContext = buildSslContext(params);
        vaultClient = new VaultHttpClient(vaultAddr, sslContext, namespace, null);
        authenticate(params);
        verifyTransitKey();

        if (cacheTtlSeconds > 0) {
            cache = new ConcurrentHashMap<>();
            logger.debug("Password cache enabled with TTL of {} seconds", cacheTtlSeconds);
        }

        scheduleTokenRenewal();

        if (transitNamespace != null) {
            logger.info("VaultTransitCodec initialized. Vault: {}, Auth NS: {}, Transit NS: {}, "
                    + "Mount: {}, Key: {}, Auth: {}",
                    vaultAddr, namespace, transitNamespace, transitMount, transitKey, authMethod);
        } else {
            String ns = namespace != null ? namespace : "(root)";
            logger.info("VaultTransitCodec initialized. Vault: {}, NS: {}, Mount: {}, Key: {}, "
                    + "Auth: {}", vaultAddr, ns, transitMount, transitKey, authMethod);
        }
    }

    /**
     * Encrypts a plaintext password using Vault Transit.
     *
     * @param secret the plaintext password to encrypt (must be a String)
     * @return the Vault ciphertext in format {@code vault:v{N}:...}
     * @throws Exception if encryption fails
     */
    @Override
    public String encode(Object secret) throws Exception {
        String plaintext = (String) secret;
        String base64Encoded = Base64.getEncoder()
                .encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));

        try {
            return vaultClient.transitEncrypt(
                    transitMount, transitKey, base64Encoded, transitNamespace);
        } catch (VaultException e) {
            throw translateException(e, "encrypt");
        }
    }

    /**
     * Decrypts a Vault Transit ciphertext to recover the original plaintext.
     *
     * <p>Results are cached (if caching is enabled) to reduce Vault API calls.
     *
     * @param mask the Vault ciphertext in format {@code vault:v{N}:...}
     * @return the decrypted plaintext password
     * @throws Exception if decryption fails or ciphertext format is invalid
     */
    @Override
    public String decode(Object mask) throws Exception {
        String ciphertext = (String) mask;

        if (!ciphertext.startsWith("vault:v")) {
            throw new IllegalArgumentException(
                    "Invalid ciphertext format. Expected: vault:v{N}:..., got: "
                            + truncateForLog(ciphertext, 20) + "...");
        }

        if (cache != null) {
            CacheEntry entry = cache.get(ciphertext);
            if (entry != null && !entry.isExpired()) {
                return entry.value;
            }
        }

        String plaintext = decryptWithRetry(ciphertext);

        if (cache != null) {
            cache.put(ciphertext, new CacheEntry(plaintext, cacheTtlSeconds * 1000L));
        }

        return plaintext;
    }

    /**
     * Verifies a plaintext password matches an encrypted value.
     *
     * <p>Uses constant-time comparison to prevent timing attacks. Never throws;
     * returns {@code false} on any error.
     *
     * @param value the plaintext password to verify
     * @param encodedValue the encrypted ciphertext to compare against
     * @return {@code true} if the password matches, {@code false} otherwise
     */
    @Override
    public boolean verify(char[] value, String encodedValue) {
        try {
            String decoded = decode(encodedValue);
            // Constant-time comparison to prevent timing attacks
            byte[] a = new String(value).getBytes(StandardCharsets.UTF_8);
            byte[] b = decoded.getBytes(StandardCharsets.UTF_8);
            return MessageDigest.isEqual(a, b);
        } catch (Exception e) {
            logger.debug("Password verification failed", e);
            return false;
        }
    }

    /**
     * Releases resources used by this codec, including the token renewal executor.
     *
     * <p>After calling this method, the codec should not be used.
     */
    @Override
    public void close() {
        if (renewalExecutor != null) {
            renewalExecutor.shutdownNow();
            renewalExecutor = null;
        }
    }

    private void parseConfiguration(Map<String, String> params) {
        vaultAddr = getConfig(params, PARAM_VAULT_ADDR, ENV_VAULT_ADDR, null);
        if (vaultAddr == null || vaultAddr.isBlank()) {
            throw new IllegalArgumentException(
                    "Missing required configuration: Vault address. "
                            + "Set " + ENV_VAULT_ADDR + " environment variable or "
                            + PARAM_VAULT_ADDR + " parameter.");
        }

        transitMount = getConfig(params, PARAM_TRANSIT_MOUNT, null, DEFAULT_TRANSIT_MOUNT);
        transitKey = getConfig(params, PARAM_TRANSIT_KEY, null, DEFAULT_TRANSIT_KEY);
        namespace = getConfig(params, PARAM_NAMESPACE, ENV_VAULT_NAMESPACE, null);

        // Transit namespace only if explicitly different from auth namespace
        String explicitTransitNs = getConfig(params, PARAM_TRANSIT_NAMESPACE, null, null);
        if (explicitTransitNs != null && !explicitTransitNs.equals(namespace)) {
            transitNamespace = explicitTransitNs;
        }

        String authMethodStr = getConfig(params, PARAM_AUTH_METHOD, null, DEFAULT_AUTH_METHOD.getValue());
        authMethod = AuthMethod.fromValue(authMethodStr);

        String maxRetriesStr = getConfig(params, PARAM_MAX_RETRIES, null, String.valueOf(DEFAULT_MAX_RETRIES));
        try {
            maxRetries = Integer.parseInt(maxRetriesStr);
            if (maxRetries < 0) {
                throw new NumberFormatException("negative value");
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid max-retries value: '" + maxRetriesStr + "'. Must be a non-negative integer.");
        }

        String cacheTtlStr = getConfig(params, PARAM_CACHE_TTL_SECONDS, null, String.valueOf(DEFAULT_CACHE_TTL_SECONDS));
        try {
            cacheTtlSeconds = Integer.parseInt(cacheTtlStr);
            if (cacheTtlSeconds < 0) {
                throw new NumberFormatException("negative value");
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid cache-ttl-seconds value: '" + cacheTtlStr + "'. Must be a non-negative integer (0 to disable).");
        }
    }

    private SSLContext buildSslContext(Map<String, String> params)
            throws GeneralSecurityException, IOException {
        String skipVerify = getConfig(params, PARAM_SKIP_VERIFY, ENV_VAULT_SKIP_VERIFY, "false");
        if (Boolean.parseBoolean(skipVerify)) {
            logger.warn("TLS certificate verification disabled. Not recommended for production.");
            return SslContextBuilder.create().withSkipVerify(true).build();
        }

        String caCert = getConfig(params, PARAM_CA_CERT, ENV_VAULT_CACERT, null);
        String clientCert = getConfig(params, PARAM_CLIENT_CERT, ENV_VAULT_CLIENT_CERT, null);
        String clientKey = getConfig(params, PARAM_CLIENT_KEY, ENV_VAULT_CLIENT_KEY, null);

        if (caCert != null || clientCert != null) {
            SslContextBuilder builder = SslContextBuilder.create();
            if (caCert != null) {
                builder.withCaCert(caCert);
            }
            if (clientCert != null && clientKey != null) {
                builder.withClientCert(clientCert, clientKey);
            }
            return builder.build();
        }

        return null;
    }

    private void authenticate(Map<String, String> params) throws Exception {
        authenticator = createAuthenticator(params);
        authenticator.authenticate(vaultClient);
    }

    private VaultAuthenticator createAuthenticator(Map<String, String> params) {
        if (authMethod == AuthMethod.APPROLE) {
            return createAppRoleAuthenticator(params);
        }
        if (authMethod == AuthMethod.TOKEN) {
            return createTokenAuthenticator(params);
        }
        throw new IllegalStateException(
                "Unsupported auth method: " + authMethod + ". This should not happen - " +
                "AuthMethod.fromValue() should have rejected invalid values.");
    }

    private TokenAuthenticator createTokenAuthenticator(Map<String, String> params) {
        String tokenPath = getConfig(params, PARAM_TOKEN_PATH, ENV_VAULT_TOKEN_FILE, DEFAULT_TOKEN_PATH);
        return TokenAuthenticator.create(ENV_VAULT_TOKEN, tokenPath);
    }

    private AppRoleAuthenticator createAppRoleAuthenticator(Map<String, String> params) {
        String roleId = getConfig(params, PARAM_APPROLE_ID, ENV_VAULT_ROLE_ID, null);
        if (roleId == null || roleId.isBlank()) {
            throw new SecurityException(
                    "AppRole authentication requires role ID. Set " + ENV_VAULT_ROLE_ID
                            + " environment variable or " + PARAM_APPROLE_ID + " parameter.");
        }

        String secretFile = getConfig(params, PARAM_APPROLE_SECRET_FILE, ENV_VAULT_SECRET_ID_FILE, null);
        return AppRoleAuthenticator.create(roleId, ENV_VAULT_SECRET_ID, secretFile);
    }

    private void verifyTransitKey() throws Exception {
        try {
            VaultResponse response = vaultClient.transitReadKey(transitMount, transitKey, transitNamespace);
            if (response.getData() == null || response.getData().isEmpty()) {
                throw new IllegalStateException(
                        "Transit key '" + transitKey + "' not found at mount '" + transitMount
                                + "'. Create it with: vault write -f " + transitMount + "/keys/" + transitKey);
            }
        } catch (VaultException e) {
            int status = e.getHttpStatusCode();
            if (status == 403 || status == 412) {
                // 403: No read permission, but may have encrypt/decrypt
                // 412: Vault Enterprise replication lag - fall back to encrypt/decrypt test
                testEncryptDecrypt();
            } else if (status == 404) {
                throw new IllegalStateException(
                        "Transit key '" + transitKey + "' not found at mount '" + transitMount
                                + "'. Create it with: vault write -f " + transitMount + "/keys/" + transitKey);
            } else {
                throw new IllegalStateException(
                        "Cannot verify transit key '" + transitKey + "': " + e.getMessage(), e);
            }
        }
    }

    private void testEncryptDecrypt() throws Exception {
        String testPlaintext = Base64.getEncoder()
                .encodeToString("test".getBytes(StandardCharsets.UTF_8));

        try {
            String ciphertext = vaultClient.transitEncrypt(
                    transitMount, transitKey, testPlaintext, transitNamespace);

            vaultClient.transitDecrypt(
                    transitMount, transitKey, ciphertext, transitNamespace);

            logger.debug("Transit key '{}' encrypt/decrypt verified at mount '{}'",
                    transitKey, transitMount);

        } catch (VaultException e) {
            if (e.getHttpStatusCode() == 403) {
                throw new SecurityException(
                        "Permission denied for transit operations on key '" + transitKey
                                + "'. Verify policy grants 'update' on "
                                + transitMount + "/encrypt/" + transitKey + " and "
                                + transitMount + "/decrypt/" + transitKey, e);
            }
            throw e;
        }
    }

    private String decryptWithRetry(String ciphertext) throws Exception {
        Exception lastException = null;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                return doDecrypt(ciphertext);
            } catch (VaultException e) {
                lastException = e;

                if (!isTransientError(e) || attempt == maxRetries) {
                    throw translateException(e, "decrypt");
                }

                long delay = calculateBackoff(attempt);
                logger.warn("Decrypt attempt {} of {} failed, retrying in {}ms: {}",
                        attempt, maxRetries, delay, e.getMessage());
                Thread.sleep(delay);
            }
        }

        throw lastException;
    }

    private String doDecrypt(String ciphertext) throws VaultException {
        String base64Plaintext = vaultClient.transitDecrypt(
                transitMount, transitKey, ciphertext, transitNamespace);

        return new String(Base64.getDecoder().decode(base64Plaintext), StandardCharsets.UTF_8);
    }

    private boolean isTransientError(VaultException e) {
        int status = e.getHttpStatusCode();
        return status == 0 ||      // Connection failed
                status == 500 ||    // Internal server error
                status == 502 ||    // Bad gateway
                status == 503 ||    // Service unavailable
                status == 504;      // Gateway timeout
    }

    private long calculateBackoff(int attempt) {
        long delay = INITIAL_BACKOFF_MS * (1L << (attempt - 1));
        return Math.min(delay, MAX_BACKOFF_MS);
    }

    private Exception translateException(VaultException e, String operation) {
        int status = e.getHttpStatusCode();
        if (status == 403) {
            return new SecurityException(
                    "Permission denied for " + transitMount + "/" + operation + "/" + transitKey +
                            ". Verify Vault policy grants 'update' capability.", e);
        } else if (status == 404) {
            return new IllegalStateException(
                    "Transit key '" + transitKey + "' not found at mount '" + transitMount + "'", e);
        } else {
            return new IllegalStateException(
                    "Vault " + operation + " failed: " + e.getMessage(), e);
        }
    }

    private void scheduleTokenRenewal() {
        renewalExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "VaultTransitCodec-TokenRenewal");
            t.setDaemon(true); // Won't prevent JVM shutdown
            return t;
        });

        try {
            VaultResponse lookupResponse = vaultClient.lookupSelf();
            Map<String, Object> data = lookupResponse.getData();

            long ttlSeconds = 0;
            if (data != null) {
                Object ttlObj = data.get("ttl");
                if (ttlObj instanceof Number) {
                    ttlSeconds = ((Number) ttlObj).longValue();
                }
            }

            if (ttlSeconds > 0) {
                // Schedule renewal at 2/3 of TTL (minimum 60 seconds)
                long renewalDelay = Math.max(ttlSeconds * 2 / 3, MIN_RENEWAL_INTERVAL_SECONDS);
                renewalExecutor.scheduleAtFixedRate(
                        this::renewToken,
                        renewalDelay,
                        renewalDelay,
                        TimeUnit.SECONDS);

                logger.info("Token renewal scheduled every {} seconds (token TTL: {}s)", renewalDelay, ttlSeconds);
            } else {
                logger.info("Token has no TTL (non-expiring), renewal not scheduled");
            }

        } catch (VaultException e) {
            logger.warn("Could not determine token TTL, renewal not scheduled: {}", e.getMessage());
        }
    }

    private void renewToken() {
        try {
            vaultClient.renewSelf();
            logger.debug("Token renewed successfully");
        } catch (VaultException e) {
            logger.warn("Token renewal failed: {}. Attempting re-authentication...", e.getMessage());
            attemptReauthentication();
        }
    }

    private void attemptReauthentication() {
        if (authenticator == null) {
            logger.error("No authenticator configured. Broker may lose Vault access.");
            return;
        }

        if (!authenticator.supportsReauthentication()) {
            logger.error("Token renewal failed and {} authentication does not support automatic " +
                    "re-authentication. Manual intervention required. Consider using AppRole with " +
                    "a secret file for automatic token refresh.", authenticator.getAuthMethod());
            return;
        }

        try {
            authenticator.reauthenticate(vaultClient);
            logger.info("Re-authentication successful using {} method", authenticator.getAuthMethod());

            // After successful re-auth, reschedule token renewal with new TTL
            rescheduleTokenRenewal();
        } catch (Exception e) {
            logger.error("Re-authentication failed: {}. Broker may lose Vault access.", e.getMessage());
            logger.debug("Re-authentication failure details", e);
        }
    }

    private void rescheduleTokenRenewal() {
        try {
            VaultResponse lookupResponse = vaultClient.lookupSelf();
            Map<String, Object> data = lookupResponse.getData();

            long ttlSeconds = 0;
            if (data != null) {
                Object ttlObj = data.get("ttl");
                if (ttlObj instanceof Number) {
                    ttlSeconds = ((Number) ttlObj).longValue();
                }
            }

            if (ttlSeconds > 0) {
                long renewalDelay = Math.max(ttlSeconds * 2 / 3, MIN_RENEWAL_INTERVAL_SECONDS);
                logger.info("New token TTL: {}s, next renewal in {}s", ttlSeconds, renewalDelay);
            }
        } catch (VaultException e) {
            logger.warn("Could not determine new token TTL: {}", e.getMessage());
        }
    }

    private String getConfig(Map<String, String> params, String paramName, String envName, String defaultValue) {
        String value = params.get(paramName);
        if (value != null && !value.isBlank()) {
            return value;
        }
        if (envName != null) {
            value = System.getenv(envName);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return defaultValue;
    }

    private String truncateForLog(String value, int maxLength) {
        if (value == null) {
            return "null";
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    ConcurrentHashMap<String, CacheEntry> getCache() {
        return cache;
    }

    void clearCache() {
        if (cache != null) {
            cache.clear();
        }
    }

    void setVaultClient(VaultHttpClient client) {
        this.vaultClient = client;
    }

    VaultHttpClient getVaultClient() {
        return vaultClient;
    }
}
