package com.hashicorp.vault.client;

import java.util.Map;

/**
 * Represents a successful response from the Vault API.
 *
 * <p>Vault responses typically have this structure:
 * <pre>{@code
 * {
 *   "data": { ... },       // For secret/logical operations
 *   "auth": { ... },       // For authentication operations
 *   "lease_id": "...",
 *   "lease_duration": 3600,
 *   "renewable": true
 * }
 * }</pre>
 */
public class VaultResponse {

    private final int status;
    private final Map<String, Object> data;
    private final Map<String, Object> auth;
    private final String leaseId;
    private final long leaseDuration;
    private final boolean renewable;

    private VaultResponse(int status, Map<String, Object> data, Map<String, Object> auth,
                          String leaseId, long leaseDuration, boolean renewable) {
        this.status = status;
        this.data = data;
        this.auth = auth;
        this.leaseId = leaseId;
        this.leaseDuration = leaseDuration;
        this.renewable = renewable;
    }

    /**
     * Parses a JSON response body into a VaultResponse.
     *
     * @param status the HTTP status code
     * @param json   the JSON response body
     * @return the parsed response
     */
    @SuppressWarnings("unchecked")
    public static VaultResponse fromJson(int status, String json) {
        if (json == null || json.isBlank()) {
            return new VaultResponse(status, null, null, null, 0, false);
        }

        Map<String, Object> root = JsonUtil.parseObject(json);
        if (root == null) {
            return new VaultResponse(status, null, null, null, 0, false);
        }

        Map<String, Object> data = (Map<String, Object>) root.get("data");
        Map<String, Object> auth = (Map<String, Object>) root.get("auth");
        String leaseId = (String) root.get("lease_id");

        long leaseDuration = 0;
        Object leaseDurationObj = root.get("lease_duration");
        if (leaseDurationObj instanceof Number) {
            leaseDuration = ((Number) leaseDurationObj).longValue();
        }

        boolean renewable = Boolean.TRUE.equals(root.get("renewable"));

        return new VaultResponse(status, data, auth, leaseId, leaseDuration, renewable);
    }

    /**
     * Gets the HTTP status code.
     *
     * @return the status code
     */
    public int getStatus() {
        return status;
    }

    /**
     * Gets the 'data' field from the response.
     *
     * <p>This field contains the actual response data for most Vault operations
     * (secrets, Transit encrypt/decrypt, etc.).
     *
     * @return the data map, or null if not present
     */
    public Map<String, Object> getData() {
        return data;
    }

    /**
     * Gets the 'auth' field from the response.
     *
     * <p>This field contains authentication information (token, policies, etc.)
     * for login and token operations.
     *
     * @return the auth map, or null if not present
     */
    public Map<String, Object> getAuth() {
        return auth;
    }

    /**
     * Gets the lease ID if the response includes a lease.
     *
     * @return the lease ID, or null if not present
     */
    public String getLeaseId() {
        return leaseId;
    }

    /**
     * Gets the lease duration in seconds.
     *
     * @return the lease duration, or 0 if not present
     */
    public long getLeaseDuration() {
        return leaseDuration;
    }

    /**
     * Checks if the lease/token is renewable.
     *
     * @return true if renewable
     */
    public boolean isRenewable() {
        return renewable;
    }

    /**
     * Gets a string value from the data field.
     *
     * @param key the key to look up
     * @return the string value, or null if not present or not a string
     */
    public String getDataString(String key) {
        if (data == null) {
            return null;
        }
        Object value = data.get(key);
        return value instanceof String ? (String) value : null;
    }

    /**
     * Gets a long value from the data field.
     *
     * @param key          the key to look up
     * @param defaultValue the value to return if not present
     * @return the long value, or defaultValue if not present
     */
    public long getDataLong(String key, long defaultValue) {
        if (data == null) {
            return defaultValue;
        }
        Object value = data.get(key);
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        return defaultValue;
    }

    /**
     * Gets a string value from the auth field.
     *
     * @param key the key to look up
     * @return the string value, or null if not present
     */
    public String getAuthString(String key) {
        if (auth == null) {
            return null;
        }
        Object value = auth.get(key);
        return value instanceof String ? (String) value : null;
    }

    /**
     * Gets a long value from the auth field.
     *
     * @param key          the key to look up
     * @param defaultValue the value to return if not present
     * @return the long value, or defaultValue
     */
    public long getAuthLong(String key, long defaultValue) {
        if (auth == null) {
            return defaultValue;
        }
        Object value = auth.get(key);
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        return defaultValue;
    }
}
