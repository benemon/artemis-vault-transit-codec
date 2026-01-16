package com.hashicorp.vault.client;

/**
 * Supported Vault authentication methods.
 *
 * @see VaultAuthenticator
 */
public enum AuthMethod {

    /**
     * Direct token authentication.
     *
     * <p>Uses a pre-existing Vault token. Does not support automatic re-authentication.
     */
    TOKEN("token"),

    /**
     * AppRole authentication.
     *
     * <p>Uses role ID and secret ID credentials. Supports automatic re-authentication
     * when configured with a dynamic secret source (file or environment variable).
     */
    APPROLE("approle");

    private final String value;

    AuthMethod(String value) {
        this.value = value;
    }

    /**
     * Returns the string value used in configuration.
     *
     * @return the configuration value (e.g., "token", "approle")
     */
    public String getValue() {
        return value;
    }

    /**
     * Parses a configuration string to an AuthMethod.
     *
     * @param value the configuration value (case-insensitive)
     * @return the corresponding AuthMethod
     * @throws IllegalArgumentException if the value is not recognized
     */
    public static AuthMethod fromValue(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Auth method cannot be null or blank");
        }
        for (AuthMethod method : values()) {
            if (method.value.equalsIgnoreCase(value)) {
                return method;
            }
        }
        throw new IllegalArgumentException(
                "Invalid auth-method: '" + value + "'. Supported values: token, approle");
    }

    @Override
    public String toString() {
        return value;
    }
}
