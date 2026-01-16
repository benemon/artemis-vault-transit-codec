package com.hashicorp.vault.client;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authenticator implementation for Vault AppRole authentication.
 *
 * <p>AppRole is a machine-oriented auth method that uses a role ID and secret ID
 * to authenticate. This authenticator supports multiple secret ID sources:
 * <ul>
 *   <li>Secret ID file path (re-read on each authentication attempt)</li>
 *   <li>Environment variable (re-read on each authentication attempt)</li>
 *   <li>Direct secret ID value (static, no re-authentication)</li>
 * </ul>
 *
 * <p><strong>Re-authentication:</strong> When using a secret file or environment variable,
 * this authenticator supports re-authentication. When the token renewal fails (e.g., max TTL
 * reached), it will re-read the secret from the configured source and perform a fresh
 * AppRole login.
 *
 * <h2>Secret ID Delivery</h2>
 * <p>Both file and environment variable approaches work well with Kubernetes:
 * <ul>
 *   <li>Vault Agent can write wrapped/unwrapped secret IDs to a shared volume</li>
 *   <li>Init containers can fetch and write secret IDs</li>
 *   <li>Sidecars can refresh environment variables</li>
 *   <li>The source is re-read on each auth attempt, allowing rotation</li>
 * </ul>
 *
 * <h2>Configuration</h2>
 * <ul>
 *   <li>{@code VAULT_ROLE_ID} or {@code approle-id} - The AppRole role ID</li>
 *   <li>{@code VAULT_SECRET_ID} - Environment variable containing secret ID</li>
 *   <li>{@code VAULT_SECRET_ID_FILE} or {@code approle-secret-file} - Path to secret file</li>
 * </ul>
 *
 * @see VaultAuthenticator
 * @see TokenAuthenticator
 */
public class AppRoleAuthenticator implements VaultAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(AppRoleAuthenticator.class);

    private final String roleId;
    private final String secretFilePath;
    private final String secretEnvVarName;
    private final String staticSecretId;
    private final String secretSource;

    /**
     * Creates an AppRoleAuthenticator with a static secret ID value.
     *
     * <p>Note: Using a static secret ID disables re-authentication capability.
     * The secret ID is typically single-use or limited-use, so once the token
     * expires, manual intervention is required.
     *
     * @param roleId       the AppRole role ID
     * @param secretId     the AppRole secret ID (static value)
     * @param secretSource description of where the secret came from (for logging)
     */
    public AppRoleAuthenticator(String roleId, String secretId, String secretSource) {
        Preconditions.requireNonBlank(roleId, "Role ID");
        Preconditions.requireNonBlank(secretId, "Secret ID");
        this.roleId = roleId;
        this.staticSecretId = secretId;
        this.secretFilePath = null;
        this.secretEnvVarName = null;
        this.secretSource = secretSource;
    }

    /**
     * Creates an AppRoleAuthenticator that reads secret ID from a file.
     *
     * <p>This constructor enables re-authentication: when token renewal fails,
     * the secret file is re-read and a fresh login is performed.
     *
     * @param roleId         the AppRole role ID
     * @param secretFilePath path to file containing the secret ID
     */
    public AppRoleAuthenticator(String roleId, String secretFilePath) {
        Preconditions.requireNonBlank(roleId, "Role ID");
        Preconditions.requireNonBlank(secretFilePath, "Secret file path");
        this.roleId = roleId;
        this.staticSecretId = null;
        this.secretFilePath = secretFilePath;
        this.secretEnvVarName = null;
        this.secretSource = "secret file: " + secretFilePath;
    }

    /**
     * Creates an AppRoleAuthenticator that reads secret ID from an environment variable.
     *
     * <p>This factory method enables re-authentication: when token renewal fails,
     * the environment variable is re-read and a fresh login is performed.
     *
     * @param roleId     the AppRole role ID
     * @param envVarName the environment variable name containing the secret ID
     * @return a new AppRoleAuthenticator configured for environment variable source
     * @throws IllegalArgumentException if roleId or envVarName is null/blank
     */
    private static AppRoleAuthenticator fromEnvironmentVariable(String roleId, String envVarName) {
        Preconditions.requireNonBlank(roleId, "Role ID");
        Preconditions.requireNonBlank(envVarName, "Environment variable name");
        return new AppRoleAuthenticator(roleId, envVarName, (Void) null);
    }

    /**
     * Private constructor for environment variable source.
     *
     * <p>The {@code Void} parameter disambiguates from the public file-based constructor.
     */
    private AppRoleAuthenticator(String roleId, String envVarName, Void marker) {
        this.roleId = roleId;
        this.staticSecretId = null;
        this.secretFilePath = null;
        this.secretEnvVarName = envVarName;
        this.secretSource = envVarName + " environment variable";
    }

    /**
     * Creates an AppRoleAuthenticator with automatic source resolution.
     *
     * <p>Resolution order for secret ID:
     * <ol>
     *   <li>Secret file at specified path (if exists and readable)</li>
     *   <li>Environment variable (if set)</li>
     * </ol>
     *
     * <p>Both sources support re-authentication by re-reading on each auth attempt.
     *
     * @param roleId         the AppRole role ID
     * @param envVarName     environment variable name for secret ID
     * @param secretFilePath path to secret file, or null
     * @return a new AppRoleAuthenticator
     * @throws SecurityException if no secret source is available
     */
    public static AppRoleAuthenticator create(String roleId, String envVarName, String secretFilePath) {
        if (roleId == null || roleId.isBlank()) {
            throw new SecurityException("AppRole role ID is required");
        }

        // Prefer secret file (if exists and readable)
        if (secretFilePath != null && !secretFilePath.isBlank()) {
            if (Files.isReadable(Path.of(secretFilePath))) {
                return new AppRoleAuthenticator(roleId, secretFilePath);
            }
            // File specified but not readable - log and fall through to env var
            logger.debug("Secret file not readable: {}, checking environment variable", secretFilePath);
        }

        // Try environment variable (supports re-auth by re-reading)
        String envSecret = System.getenv(envVarName);
        if (envSecret != null && !envSecret.isBlank()) {
            if (secretFilePath != null && !secretFilePath.isBlank()) {
                logger.info("Using secret ID from {} (secret file {} not available)",
                        envVarName, secretFilePath);
            }
            // Create authenticator that will re-read env var on re-auth
            return fromEnvironmentVariable(roleId, envVarName);
        }

        throw new SecurityException(
                "AppRole authentication requires secret ID. Set " + envVarName +
                        " environment variable or provide a readable secret file path.");
    }

    @Override
    public AuthMethod getAuthMethod() {
        return AuthMethod.APPROLE;
    }

    @Override
    public void authenticate(VaultHttpClient client) throws VaultException {
        String currentSecretId = resolveSecretId();
        performLogin(client, currentSecretId);
        logger.info("AppRole authentication successful using {}", secretSource);
    }

    @Override
    public boolean supportsReauthentication() {
        // Re-authentication is supported when using a file or env var (not static value)
        return secretFilePath != null || secretEnvVarName != null;
    }

    @Override
    public void reauthenticate(VaultHttpClient client) throws VaultException {
        if (!supportsReauthentication()) {
            throw new UnsupportedOperationException(
                    "AppRole re-authentication requires a dynamic secret source. " +
                            "The current configuration uses a static secret ID from " + secretSource + ". " +
                            "Configure 'approle-secret-file', VAULT_SECRET_ID_FILE, or VAULT_SECRET_ID " +
                            "for automatic re-authentication.");
        }

        logger.info("Attempting AppRole re-authentication using {}", secretSource);
        String freshSecretId = resolveSecretId();
        performLogin(client, freshSecretId);
        logger.info("AppRole re-authentication successful");
    }

    private String resolveSecretId() {
        // Static secret (no re-read)
        if (staticSecretId != null) {
            return staticSecretId;
        }

        // Read from file
        if (secretFilePath != null) {
            return readSecretFile();
        }

        // Read from environment variable
        if (secretEnvVarName != null) {
            return readSecretEnvVar();
        }

        throw new IllegalStateException("No secret source configured");
    }

    private String readSecretFile() {
        try {
            String content = Files.readString(Path.of(secretFilePath)).trim();
            if (content.isBlank()) {
                throw new SecurityException("Secret file is empty: " + secretFilePath);
            }
            return content;
        } catch (IOException e) {
            throw new SecurityException("Cannot read secret file: " + secretFilePath, e);
        }
    }

    private String readSecretEnvVar() {
        String value = System.getenv(secretEnvVarName);
        if (value == null || value.isBlank()) {
            throw new SecurityException("Environment variable " + secretEnvVarName +
                    " is not set or is empty");
        }
        return value;
    }

    private void performLogin(VaultHttpClient client, String secretIdValue) throws VaultException {
        try {
            String token = client.loginAppRole(roleId, secretIdValue);
            client.setToken(token);
        } catch (VaultException e) {
            throw new SecurityException(
                    "AppRole authentication failed: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the role ID used for authentication.
     *
     * @return the role ID
     */
    public String getRoleId() {
        return roleId;
    }

    /**
     * Returns a description of the secret source (for logging).
     *
     * @return the secret source description
     */
    public String getSecretSource() {
        return secretSource;
    }
}
