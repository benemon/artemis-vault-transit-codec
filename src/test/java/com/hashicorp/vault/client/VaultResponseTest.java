package com.hashicorp.vault.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for VaultResponse parsing.
 */
class VaultResponseTest {

    @Test
    void fromJson_withNullBody_returnsEmptyResponse() {
        VaultResponse response = VaultResponse.fromJson(200, null);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getData()).isNull();
        assertThat(response.getAuth()).isNull();
    }

    @Test
    void fromJson_withEmptyBody_returnsEmptyResponse() {
        VaultResponse response = VaultResponse.fromJson(200, "");

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getData()).isNull();
        assertThat(response.getAuth()).isNull();
    }

    @Test
    void fromJson_withDataField_parsesData() {
        String json = "{\"data\":{\"ciphertext\":\"vault:v1:abc\"}}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getData()).containsEntry("ciphertext", "vault:v1:abc");
    }

    @Test
    void fromJson_withAuthField_parsesAuth() {
        String json = "{\"auth\":{\"client_token\":\"hvs.test\",\"lease_duration\":3600}}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getAuth()).containsEntry("client_token", "hvs.test");
        // Gson parses numbers as Double by default
        assertThat(((Number) response.getAuth().get("lease_duration")).intValue()).isEqualTo(3600);
    }

    @Test
    void fromJson_withLeaseInfo_parsesLeaseFields() {
        String json = "{\"lease_id\":\"auth/token/create/123\",\"lease_duration\":3600,\"renewable\":true}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getLeaseId()).isEqualTo("auth/token/create/123");
        assertThat(response.getLeaseDuration()).isEqualTo(3600);
        assertThat(response.isRenewable()).isTrue();
    }

    @Test
    void fromJson_withoutLeaseInfo_returnsDefaults() {
        String json = "{\"data\":{}}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getLeaseId()).isNull();
        assertThat(response.getLeaseDuration()).isEqualTo(0);
        assertThat(response.isRenewable()).isFalse();
    }

    @Test
    void getDataString_withValidKey_returnsValue() {
        String json = "{\"data\":{\"plaintext\":\"dGVzdA==\"}}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getDataString("plaintext")).isEqualTo("dGVzdA==");
    }

    @Test
    void getDataString_withMissingKey_returnsNull() {
        String json = "{\"data\":{\"other\":\"value\"}}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getDataString("missing")).isNull();
    }

    @Test
    void getDataString_withNullData_returnsNull() {
        VaultResponse response = VaultResponse.fromJson(200, "{}");

        assertThat(response.getDataString("any")).isNull();
    }

    @Test
    void getDataLong_withValidKey_returnsValue() {
        String json = "{\"data\":{\"ttl\":3600}}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getDataLong("ttl", 0)).isEqualTo(3600);
    }

    @Test
    void getDataLong_withMissingKey_returnsDefault() {
        String json = "{\"data\":{}}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getDataLong("missing", 42)).isEqualTo(42);
    }

    @Test
    void getAuthString_withValidKey_returnsValue() {
        String json = "{\"auth\":{\"client_token\":\"hvs.test\"}}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getAuthString("client_token")).isEqualTo("hvs.test");
    }

    @Test
    void getAuthLong_withValidKey_returnsValue() {
        String json = "{\"auth\":{\"lease_duration\":7200}}";
        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getAuthLong("lease_duration", 0)).isEqualTo(7200);
    }

    @Test
    void fromJson_transitEncryptResponse_parsesCorrectly() {
        String json = """
                {
                    "data": {
                        "ciphertext": "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM96XVZ",
                        "key_version": 1
                    }
                }
                """;

        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getDataString("ciphertext"))
                .startsWith("vault:v1:");
        assertThat(response.getDataLong("key_version", 0)).isEqualTo(1);
    }

    @Test
    void fromJson_transitDecryptResponse_parsesCorrectly() {
        String json = """
                {
                    "data": {
                        "plaintext": "dGVzdA=="
                    }
                }
                """;

        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getDataString("plaintext")).isEqualTo("dGVzdA==");
    }

    @Test
    void fromJson_tokenLookupResponse_parsesCorrectly() {
        String json = """
                {
                    "data": {
                        "accessor": "acc123",
                        "ttl": 3600,
                        "renewable": true,
                        "policies": ["default", "transit"]
                    }
                }
                """;

        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getDataLong("ttl", 0)).isEqualTo(3600);
        assertThat(response.getData().get("renewable")).isEqualTo(true);
    }

    @Test
    void fromJson_appRoleLoginResponse_parsesCorrectly() {
        String json = """
                {
                    "auth": {
                        "client_token": "hvs.CAESIJlU",
                        "accessor": "acc456",
                        "policies": ["default", "transit-policy"],
                        "lease_duration": 3600,
                        "renewable": true
                    }
                }
                """;

        VaultResponse response = VaultResponse.fromJson(200, json);

        assertThat(response.getAuthString("client_token")).isEqualTo("hvs.CAESIJlU");
        assertThat(response.getAuthLong("lease_duration", 0)).isEqualTo(3600);
    }
}
