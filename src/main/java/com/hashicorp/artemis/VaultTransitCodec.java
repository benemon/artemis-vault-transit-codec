package com.hashicorp.artemis;

import com.hashicorp.vault.client.SslContextBuilder;
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

    // Environment variable names (standard Vault naming)
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

    // Configuration parameter names (broker.xml)
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

    // Default values
    private static final String DEFAULT_TRANSIT_MOUNT = "transit";
    private static final String DEFAULT_TRANSIT_KEY = "artemis";
    private static final String DEFAULT_AUTH_METHOD = "token";
    private static final String DEFAULT_TOKEN_PATH = "/vault/secrets/.vault-token";
    private static final int DEFAULT_CACHE_TTL_SECONDS = 300;
    private static final int DEFAULT_MAX_RETRIES = 3;
    private static final long INITIAL_BACKOFF_MS = 100L;
    private static final long MAX_BACKOFF_MS = 800L;
    private static final long MIN_RENEWAL_INTERVAL_SECONDS = 60L;

    // Configuration (set during init)
    private String vaultAddr;
    private String transitMount;
    private String transitKey;
    private String authMethod;
    private String namespace;
    private String transitNamespace;
    private int maxRetries;
    private int cacheTtlSeconds;

    // Runtime state (thread-safe)
    private VaultHttpClient vaultClient;
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

        // 1. Parse and validate configuration
        parseConfiguration(params);

        // 2. Build SSL context
        SSLContext sslContext = buildSslContext(params);

        // 3. Create Vault HTTP client
        vaultClient = new VaultHttpClient(vaultAddr, sslContext, namespace, null);

        // 4. Authenticate (will set token on client)
        authenticate(params);

        // 5. Verify Transit key is accessible
        verifyTransitKey();

        // 6. Initialize cache if enabled
        if (cacheTtlSeconds > 0) {
            cache = new ConcurrentHashMap<>();
            logger.debug("Password cache enabled with TTL of {} seconds", cacheTtlSeconds);
        } else {
            logger.debug("Password cache disabled");
        }

        // 7. Schedule token renewal
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
        logger.debug("VaultTransitCodec.encode() called - encrypting value via Vault Transit");
        logger.debug("Encrypting using transit mount '{}', key '{}'", transitMount, transitKey);

        String plaintext = (String) secret;

        // Base64 encode the plaintext (required by Vault Transit)
        String base64Encoded = Base64.getEncoder()
                .encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));

        try {
            String ciphertext = vaultClient.transitEncrypt(
                    transitMount, transitKey, base64Encoded, transitNamespace);

            logger.debug("VaultTransitCodec.encode() completed - value encrypted successfully");
            logger.debug("Ciphertext prefix: {}", truncateForLog(ciphertext, 20));
            return ciphertext;

        } catch (VaultException e) {
            logger.error("VaultTransitCodec.encode() failed: {}", e.getMessage());
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
        logger.debug("VaultTransitCodec.decode() called - decrypting value via Vault Transit");
        String ciphertext = (String) mask;
        logger.debug("Decrypting ciphertext with prefix: {}", truncateForLog(ciphertext, 20));

        // Validate ciphertext format
        if (!ciphertext.startsWith("vault:v")) {
            logger.error("Invalid ciphertext format - does not start with 'vault:v'");
            throw new IllegalArgumentException(
                    "Invalid ciphertext format. Expected: vault:v{N}:..., got: "
                            + truncateForLog(ciphertext, 20) + "...");
        }

        // Check cache first
        if (cache != null) {
            CacheEntry entry = cache.get(ciphertext);
            if (entry != null && !entry.isExpired()) {
                logger.debug("VaultTransitCodec.decode() completed - cache hit (no Vault call)");
                logger.debug("Returning cached plaintext");
                return entry.value;
            }
        }

        // Decrypt with retry logic
        String plaintext = decryptWithRetry(ciphertext);

        // Cache the result
        if (cache != null) {
            cache.put(ciphertext, new CacheEntry(plaintext, cacheTtlSeconds * 1000L));
            logger.debug("Cached decrypted value with TTL of {} seconds", cacheTtlSeconds);
        }

        logger.debug("VaultTransitCodec.decode() completed - value decrypted successfully");
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
        logger.debug("VaultTransitCodec.verify() called - verifying password against encrypted value");
        try {
            String decoded = decode(encodedValue);
            // Use constant-time comparison to prevent timing attacks
            byte[] a = new String(value).getBytes(StandardCharsets.UTF_8);
            byte[] b = decoded.getBytes(StandardCharsets.UTF_8);
            boolean matches = MessageDigest.isEqual(a, b);
            logger.debug("VaultTransitCodec.verify() completed - match: {}", matches);
            return matches;
        } catch (Exception e) {
            // Never throw from verify() - return false on any error
            logger.warn("VaultTransitCodec.verify() failed with exception: {}", e.getMessage());
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

    // --- Configuration parsing ---

    private void parseConfiguration(Map<String, String> params) {
        // Vault address (required)
        vaultAddr = getConfig(params, PARAM_VAULT_ADDR, ENV_VAULT_ADDR, null);
        if (vaultAddr == null || vaultAddr.isBlank()) {
            throw new IllegalArgumentException(
                    "Missing required configuration: Vault address. "
                            + "Set " + ENV_VAULT_ADDR + " environment variable or "
                            + PARAM_VAULT_ADDR + " parameter.");
        }

        // Transit mount path (allows cross-namespace access)
        transitMount = getConfig(params, PARAM_TRANSIT_MOUNT, null, DEFAULT_TRANSIT_MOUNT);

        // Transit key
        transitKey = getConfig(params, PARAM_TRANSIT_KEY, null, DEFAULT_TRANSIT_KEY);

        // Vault namespace (for Vault Enterprise)
        namespace = getConfig(params, PARAM_NAMESPACE, ENV_VAULT_NAMESPACE, null);
        if (namespace != null) {
            logger.debug("Using Vault namespace for auth: {}", namespace);
        }

        // Transit namespace (only if explicitly configured and different from auth namespace)
        String explicitTransitNs = getConfig(params, PARAM_TRANSIT_NAMESPACE, null, null);
        if (explicitTransitNs != null && !explicitTransitNs.equals(namespace)) {
            transitNamespace = explicitTransitNs;
            logger.debug("Using separate namespace for Transit operations: {}", transitNamespace);
        } else {
            transitNamespace = null;  // Will use same namespace as auth
        }

        // Authentication method
        authMethod = getConfig(params, PARAM_AUTH_METHOD, null, DEFAULT_AUTH_METHOD);
        if (!authMethod.equals("token") && !authMethod.equals("approle")) {
            throw new IllegalArgumentException(
                    "Invalid auth-method: '" + authMethod + "'. Supported values: token, approle");
        }

        // Max retries
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

        // Cache TTL
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

    /**
     * Builds SSL context from configuration parameters.
     */
    private SSLContext buildSslContext(Map<String, String> params)
            throws GeneralSecurityException, IOException {
        String skipVerify = getConfig(
                params, PARAM_SKIP_VERIFY, ENV_VAULT_SKIP_VERIFY, "false");
        if (Boolean.parseBoolean(skipVerify)) {
            logger.warn("TLS certificate verification disabled. Not recommended for production.");
            return SslContextBuilder.create()
                    .withSkipVerify(true)
                    .build();
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

        // No custom SSL config - use default
        return null;
    }

    // --- Authentication ---

    private void authenticate(Map<String, String> params) throws Exception {
        if ("approle".equals(authMethod)) {
            authenticateAppRole(params);
        } else {
            authenticateToken(params);
        }
    }

    private void authenticateToken(Map<String, String> params) throws Exception {
        // Resolution order: VAULT_TOKEN env → VAULT_TOKEN_FILE / token-path file
        String token = System.getenv(ENV_VAULT_TOKEN);
        String tokenSource = ENV_VAULT_TOKEN + " environment variable";

        if (token == null || token.isBlank()) {
            // Try token file
            String tokenPath = getConfig(
                    params, PARAM_TOKEN_PATH, ENV_VAULT_TOKEN_FILE, DEFAULT_TOKEN_PATH);
            token = readFileContents(tokenPath);
            tokenSource = "token file: " + tokenPath;
        }

        if (token == null || token.isBlank()) {
            throw new SecurityException(
                    "No Vault token found. Set " + ENV_VAULT_TOKEN + " environment variable, "
                            + "or configure token file via " + ENV_VAULT_TOKEN_FILE + " / "
                            + PARAM_TOKEN_PATH + " parameter.");
        }

        vaultClient.setToken(token);
        logger.info("Token authentication configured using {}", tokenSource);
    }

    private void authenticateAppRole(Map<String, String> params) throws Exception {
        // Role ID resolution
        String roleId = getConfig(params, PARAM_APPROLE_ID, ENV_VAULT_ROLE_ID, null);
        if (roleId == null || roleId.isBlank()) {
            throw new SecurityException(
                    "AppRole authentication requires role ID. Set " + ENV_VAULT_ROLE_ID
                            + " environment variable or " + PARAM_APPROLE_ID + " parameter.");
        }

        // Secret ID resolution: VAULT_SECRET_ID env → secret file
        String secretId = System.getenv(ENV_VAULT_SECRET_ID);
        String secretSource = ENV_VAULT_SECRET_ID + " environment variable";

        if (secretId == null || secretId.isBlank()) {
            String secretFile = getConfig(
                    params, PARAM_APPROLE_SECRET_FILE, ENV_VAULT_SECRET_ID_FILE, null);
            if (secretFile != null) {
                secretId = readFileContents(secretFile);
                secretSource = "secret file: " + secretFile;
            }
        }

        if (secretId == null || secretId.isBlank()) {
            throw new SecurityException(
                    "AppRole authentication requires secret ID. Set " + ENV_VAULT_SECRET_ID
                            + " environment variable, or configure secret file via "
                            + ENV_VAULT_SECRET_ID_FILE + " / " + PARAM_APPROLE_SECRET_FILE
                            + " parameter.");
        }

        try {
            String token = vaultClient.loginAppRole(roleId, secretId);
            vaultClient.setToken(token);
            logger.info("AppRole authentication successful using {} for secret ID", secretSource);
        } catch (VaultException e) {
            throw new SecurityException(
                    "AppRole authentication failed: " + e.getMessage(), e);
        }
    }

    // --- Transit key verification ---

    private void verifyTransitKey() throws Exception {
        try {
            // Try to read key info - verifies the key exists and we have access
            VaultResponse response = vaultClient.transitReadKey(
                    transitMount, transitKey, transitNamespace);

            // Empty response means key not found
            if (response.getData() == null || response.getData().isEmpty()) {
                throw new IllegalStateException(
                        "Transit key '" + transitKey + "' not found at mount '"
                                + transitMount + "'. Create it with: vault write -f "
                                + transitMount + "/keys/" + transitKey);
            }

            logger.debug("Transit key '{}' verified at mount '{}'", transitKey, transitMount);

        } catch (VaultException e) {
            int status = e.getHttpStatusCode();
            if (status == 403 || status == 412) {
                // 403: No read permission, but may have encrypt/decrypt
                // 412: Vault Enterprise replication lag on reads
                // Both cases: fall back to testing encrypt/decrypt (writes are consistent)
                logger.debug("Cannot read transit key ({}), testing encrypt/decrypt", status);
                testEncryptDecrypt();
            } else if (status == 404) {
                throw new IllegalStateException(
                        "Transit key '" + transitKey + "' not found at mount '"
                                + transitMount + "'. Create it with: vault write -f "
                                + transitMount + "/keys/" + transitKey);
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

    // --- Decrypt with retry ---

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
        // Exponential backoff: 100ms, 200ms, 400ms, ...
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

    // --- Token renewal ---

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
            logger.error("Token renewal failed: {}. Broker may lose Vault access when token expires.", e.getMessage());
            // For AppRole, could attempt re-authentication here in a future enhancement
        }
    }

    // --- Utility methods ---

    /**
     * Get configuration value with resolution order: param → env → default.
     */
    private String getConfig(Map<String, String> params, String paramName, String envName, String defaultValue) {
        // Check broker.xml parameter first
        String value = params.get(paramName);
        if (value != null && !value.isBlank()) {
            return value;
        }

        // Check environment variable
        if (envName != null) {
            value = System.getenv(envName);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }

        // Return default
        return defaultValue;
    }

    /**
     * Read contents of a file, returning null if file doesn't exist or can't be read.
     */
    private String readFileContents(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        try {
            String contents = Files.readString(Path.of(path));
            return contents.trim();
        } catch (IOException e) {
            logger.debug("Could not read file {}: {}", path, e.getMessage());
            return null;
        }
    }

    /**
     * Truncate string for logging (avoid logging full ciphertext).
     */
    private String truncateForLog(String value, int maxLength) {
        if (value == null) {
            return "null";
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    // --- For testing ---

    /**
     * Package-private getter for testing cache state.
     */
    ConcurrentHashMap<String, CacheEntry> getCache() {
        return cache;
    }

    /**
     * Package-private method to clear cache for testing.
     */
    void clearCache() {
        if (cache != null) {
            cache.clear();
        }
    }

    /**
     * Package-private getter for injecting a mock VaultHttpClient in tests.
     */
    void setVaultClient(VaultHttpClient client) {
        this.vaultClient = client;
    }

    /**
     * Package-private getter for the Vault client (for testing).
     */
    VaultHttpClient getVaultClient() {
        return vaultClient;
    }
}
