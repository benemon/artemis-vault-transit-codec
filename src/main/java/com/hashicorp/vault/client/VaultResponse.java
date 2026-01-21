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

    public int getStatus() {
        return status;
    }

    /** Contains response data for secret/Transit operations. */
    public Map<String, Object> getData() {
        return data;
    }

    /** Contains authentication info (token, policies) for login operations. */
    public Map<String, Object> getAuth() {
        return auth;
    }

    public String getLeaseId() {
        return leaseId;
    }

    public long getLeaseDuration() {
        return leaseDuration;
    }

    public boolean isRenewable() {
        return renewable;
    }

    public String getDataString(String key) {
        if (data == null) {
            return null;
        }
        Object value = data.get(key);
        return value instanceof String ? (String) value : null;
    }

    public long getDataLong(String key, long defaultValue) {
        if (data == null) {
            return defaultValue;
        }
        Object value = data.get(key);
        return value instanceof Number ? ((Number) value).longValue() : defaultValue;
    }

    public String getAuthString(String key) {
        if (auth == null) {
            return null;
        }
        Object value = auth.get(key);
        return value instanceof String ? (String) value : null;
    }

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
