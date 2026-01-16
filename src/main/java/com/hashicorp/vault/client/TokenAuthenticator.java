package com.hashicorp.vault.client;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authenticator implementation for static Vault token authentication.
 *
 * <p>This authenticator supports two token sources:
 * <ul>
 *   <li>Direct token value (from environment variable or parameter)</li>
 *   <li>Token file path (token is read from file at initialization)</li>
 * </ul>
 *
 * <p><strong>Re-authentication:</strong> This authenticator does not support re-authentication.
 * When the token expires or becomes invalid, manual intervention is required. For
 * automated token refresh, consider using AppRole or another dynamic auth method.
 *
 * <h2>Configuration</h2>
 * <ul>
 *   <li>{@code VAULT_TOKEN} - Environment variable containing the token</li>
 *   <li>{@code VAULT_TOKEN_FILE} or {@code token-path} - Path to file containing token</li>
 * </ul>
 *
 * @see VaultAuthenticator
 * @see AppRoleAuthenticator
 */
public class TokenAuthenticator implements VaultAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(TokenAuthenticator.class);

    private final String token;
    private final String tokenSource;

    /**
     * Creates a TokenAuthenticator with a direct token value.
     *
     * @param token       the Vault token
     * @param tokenSource description of where the token came from (for logging)
     */
    public TokenAuthenticator(String token, String tokenSource) {
        Preconditions.requireNonBlank(token, "Token");
        this.token = token;
        this.tokenSource = tokenSource;
    }

    /**
     * Creates a TokenAuthenticator from environment variable or file.
     *
     * <p>Resolution order:
     * <ol>
     *   <li>Environment variable (if envVarName is provided and set)</li>
     *   <li>Token file at specified path</li>
     * </ol>
     *
     * @param envVarName    environment variable name (e.g., "VAULT_TOKEN"), or null to skip env check
     * @param tokenFilePath fallback token file path, or null
     * @return a new TokenAuthenticator
     * @throws SecurityException if no token source is available
     */
    public static TokenAuthenticator create(String envVarName, String tokenFilePath) {
        // Try environment variable first (if specified)
        if (envVarName != null && !envVarName.isBlank()) {
            String envToken = System.getenv(envVarName);
            if (envToken != null && !envToken.isBlank()) {
                return new TokenAuthenticator(envToken, envVarName + " environment variable");
            }
        }

        // Try token file
        if (tokenFilePath != null && !tokenFilePath.isBlank()) {
            try {
                String token = Files.readString(Path.of(tokenFilePath)).trim();
                if (token.isBlank()) {
                    throw new SecurityException("Token file is empty: " + tokenFilePath);
                }
                return new TokenAuthenticator(token, "token file: " + tokenFilePath);
            } catch (IOException e) {
                throw new SecurityException("Cannot read token file: " + tokenFilePath, e);
            }
        }

        // Build helpful error message
        if (envVarName != null && !envVarName.isBlank()) {
            throw new SecurityException(
                    "No Vault token found. Set " + envVarName + " environment variable " +
                            "or provide a token file path.");
        } else {
            throw new SecurityException("No Vault token found. Provide a token file path.");
        }
    }

    @Override
    public AuthMethod getAuthMethod() {
        return AuthMethod.TOKEN;
    }

    @Override
    public void authenticate(VaultHttpClient client) {
        client.setToken(token);
        logger.info("Token authentication configured using {}", tokenSource);
    }

    @Override
    public boolean supportsReauthentication() {
        return false;
    }

    @Override
    public void reauthenticate(VaultHttpClient client) {
        throw new UnsupportedOperationException(
                "Token authentication does not support re-authentication. " +
                        "The token must be renewed or replaced manually. " +
                        "Consider using AppRole authentication for automatic token refresh.");
    }

    /**
     * Returns a description of the token source (for logging).
     *
     * @return the token source description
     */
    public String getTokenSource() {
        return tokenSource;
    }
}
