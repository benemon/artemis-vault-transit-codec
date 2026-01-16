package com.hashicorp.vault.client;

import java.util.List;

/**
 * Exception thrown when a Vault API operation fails.
 *
 * <p>This exception captures both the HTTP status code and the error message(s)
 * returned by Vault. Status code 0 indicates a connection failure (timeout,
 * network error, etc.).
 */
public class VaultException extends Exception {

    private final int httpStatusCode;

    /**
     * Creates a new VaultException.
     *
     * @param message        the error message
     * @param httpStatusCode the HTTP status code (0 for connection errors)
     */
    public VaultException(String message, int httpStatusCode) {
        super(message);
        this.httpStatusCode = httpStatusCode;
    }

    /**
     * Creates a new VaultException with a cause.
     *
     * @param message        the error message
     * @param httpStatusCode the HTTP status code
     * @param cause          the underlying cause
     */
    public VaultException(String message, int httpStatusCode, Throwable cause) {
        super(message, cause);
        this.httpStatusCode = httpStatusCode;
    }

    /**
     * Gets the HTTP status code from the Vault response.
     *
     * @return the status code, or 0 if the request failed before receiving a response
     */
    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    /**
     * Creates a VaultException from an HTTP error response.
     *
     * @param statusCode the HTTP status code
     * @param body       the response body (may contain JSON error details)
     * @return a new VaultException with parsed error message
     */
    public static VaultException fromResponse(int statusCode, String body) {
        String message = parseErrorMessage(statusCode, body);
        return new VaultException(message, statusCode);
    }

    private static String parseErrorMessage(int statusCode, String body) {
        if (body == null || body.isBlank()) {
            return "Vault returned status " + statusCode;
        }

        try {
            // Vault error responses have format: {"errors": ["message1", "message2"]}
            List<String> errors = JsonUtil.parseErrors(body);
            if (errors != null && !errors.isEmpty()) {
                return String.join("; ", errors);
            }
        } catch (Exception e) {
            // Fall through to default message
        }

        // If we can't parse the errors, return the raw body (truncated)
        String truncated = body.length() > 200 ? body.substring(0, 200) + "..." : body;
        return "Vault returned status " + statusCode + ": " + truncated;
    }

    @Override
    public String toString() {
        return "VaultException{" +
                "message='" + getMessage() + '\'' +
                ", httpStatusCode=" + httpStatusCode +
                '}';
    }
}
