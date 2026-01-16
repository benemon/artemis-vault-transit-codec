package com.hashicorp.vault.client;

/**
 * Interface for Vault authentication strategies.
 *
 * <p>This interface abstracts the authentication mechanism used to obtain and refresh
 * Vault tokens. Implementations handle specific auth methods (Token, AppRole, AWS, Kubernetes, etc.)
 * and provide a consistent interface for initial authentication and re-authentication
 * when token renewal fails.
 *
 * <p>The design follows the Strategy pattern, allowing different auth methods to be
 * plugged in without changing the core codec logic.
 *
 * <h2>Token Lifecycle</h2>
 * <ol>
 *   <li>{@link #authenticate(VaultHttpClient)} - Called during initialization to obtain initial token</li>
 *   <li>Token renewal - Handled by VaultHttpClient.renewSelf() at regular intervals</li>
 *   <li>{@link #reauthenticate(VaultHttpClient)} - Called when renewal fails (e.g., max TTL reached)</li>
 * </ol>
 *
 * <h2>Implementing New Auth Methods</h2>
 * <p>To add support for a new Vault auth method (e.g., AWS IAM, Kubernetes):
 * <ol>
 *   <li>Create a new class implementing this interface</li>
 *   <li>Implement {@link #authenticate} to perform initial auth and set token</li>
 *   <li>Implement {@link #reauthenticate} to obtain fresh credentials and re-auth</li>
 *   <li>Update VaultTransitCodec to recognize the new auth method name</li>
 * </ol>
 *
 * @see TokenAuthenticator
 * @see AppRoleAuthenticator
 */
public interface VaultAuthenticator {

    /**
     * Returns the authentication method used by this authenticator.
     *
     * <p>Used for logging and configuration matching.
     *
     * @return the auth method
     */
    AuthMethod getAuthMethod();

    /**
     * Performs initial authentication and sets the token on the client.
     *
     * <p>This method is called during codec initialization. It should obtain a Vault token
     * using the configured credentials and call {@link VaultHttpClient#setToken(String)}.
     *
     * @param client the Vault HTTP client to authenticate
     * @throws VaultException if authentication fails due to Vault errors
     * @throws SecurityException if credentials are missing or invalid
     */
    void authenticate(VaultHttpClient client) throws VaultException;

    /**
     * Indicates whether this authenticator supports re-authentication.
     *
     * <p>Some auth methods can re-authenticate when the token expires or becomes invalid:
     * <ul>
     *   <li>AppRole: Can re-read secret ID from file and login again</li>
     *   <li>AWS: Can obtain fresh instance credentials</li>
     *   <li>Kubernetes: Can read fresh service account token</li>
     *   <li>Static Token: Cannot re-authenticate (token is fixed)</li>
     * </ul>
     *
     * @return true if {@link #reauthenticate(VaultHttpClient)} can obtain a new token
     */
    boolean supportsReauthentication();

    /**
     * Attempts to re-authenticate and obtain a fresh token.
     *
     * <p>This method is called when token renewal fails, typically because:
     * <ul>
     *   <li>Token has reached its max TTL and cannot be renewed</li>
     *   <li>Token was revoked</li>
     *   <li>Token accessor was invalidated</li>
     * </ul>
     *
     * <p>Implementations should:
     * <ol>
     *   <li>Obtain fresh credentials (e.g., re-read secret file, fetch IAM credentials)</li>
     *   <li>Perform authentication with Vault</li>
     *   <li>Set the new token on the client via {@link VaultHttpClient#setToken(String)}</li>
     * </ol>
     *
     * <p>If this authenticator does not support re-authentication
     * ({@link #supportsReauthentication()} returns false), this method should throw
     * an {@link UnsupportedOperationException}.
     *
     * @param client the Vault HTTP client to re-authenticate
     * @throws VaultException if re-authentication fails due to Vault errors
     * @throws SecurityException if credentials cannot be obtained
     * @throws UnsupportedOperationException if re-authentication is not supported
     */
    void reauthenticate(VaultHttpClient client) throws VaultException;
}
