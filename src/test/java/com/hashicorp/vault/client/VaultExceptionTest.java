package com.hashicorp.vault.client;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for VaultException error parsing.
 */
class VaultExceptionTest {

    @Test
    void constructor_withMessageAndStatus_setsFields() {
        VaultException ex = new VaultException("test error", 403);

        assertThat(ex.getMessage()).isEqualTo("test error");
        assertThat(ex.getHttpStatusCode()).isEqualTo(403);
    }

    @Test
    void constructor_withCause_setsCause() {
        RuntimeException cause = new RuntimeException("cause");
        VaultException ex = new VaultException("test error", 500, cause);

        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    void fromResponse_withNullBody_returnsStatusMessage() {
        VaultException ex = VaultException.fromResponse(404, null);

        assertThat(ex.getMessage()).isEqualTo("Vault returned status 404");
        assertThat(ex.getHttpStatusCode()).isEqualTo(404);
    }

    @Test
    void fromResponse_withEmptyBody_returnsStatusMessage() {
        VaultException ex = VaultException.fromResponse(500, "");

        assertThat(ex.getMessage()).isEqualTo("Vault returned status 500");
        assertThat(ex.getHttpStatusCode()).isEqualTo(500);
    }

    @Test
    void fromResponse_withSingleError_parsesErrorMessage() {
        String body = "{\"errors\":[\"permission denied\"]}";
        VaultException ex = VaultException.fromResponse(403, body);

        assertThat(ex.getMessage()).isEqualTo("permission denied");
        assertThat(ex.getHttpStatusCode()).isEqualTo(403);
    }

    @Test
    void fromResponse_withMultipleErrors_joinsWithSemicolon() {
        String body = "{\"errors\":[\"error one\",\"error two\"]}";
        VaultException ex = VaultException.fromResponse(400, body);

        assertThat(ex.getMessage()).isEqualTo("error one; error two");
    }

    @Test
    void fromResponse_withEmptyErrorsArray_returnsStatusWithBody() {
        String body = "{\"errors\":[]}";
        VaultException ex = VaultException.fromResponse(400, body);

        // Empty array means no errors to join, falls through to body message
        assertThat(ex.getMessage()).contains("400");
    }

    @Test
    void fromResponse_withNonJsonBody_returnsTruncatedBody() {
        String body = "This is not JSON";
        VaultException ex = VaultException.fromResponse(500, body);

        assertThat(ex.getMessage()).contains("500").contains("This is not JSON");
    }

    @Test
    void fromResponse_withVeryLongBody_truncatesBody() {
        String body = "A".repeat(500);
        VaultException ex = VaultException.fromResponse(500, body);

        assertThat(ex.getMessage()).hasSizeLessThan(300);
        assertThat(ex.getMessage()).endsWith("...");
    }

    @Test
    void fromResponse_withVaultErrorResponse_parsesCorrectly() {
        // Actual Vault error response format
        String body = """
                {
                    "errors": [
                        "1 error occurred:\\n\\t* permission denied\\n\\n"
                    ]
                }
                """;
        VaultException ex = VaultException.fromResponse(403, body);

        assertThat(ex.getMessage()).contains("permission denied");
    }

    @Test
    void toString_includesMessageAndStatus() {
        VaultException ex = new VaultException("test error", 403);

        assertThat(ex.toString())
                .contains("VaultException")
                .contains("test error")
                .contains("403");
    }

    @Test
    void getHttpStatusCode_withZero_indicatesConnectionError() {
        VaultException ex = new VaultException("Connection refused", 0);

        assertThat(ex.getHttpStatusCode()).isEqualTo(0);
    }

    // --- Common Vault error scenarios ---

    @Test
    void fromResponse_401_unauthorized() {
        String body = "{\"errors\":[\"missing client token\"]}";
        VaultException ex = VaultException.fromResponse(401, body);

        assertThat(ex.getHttpStatusCode()).isEqualTo(401);
        assertThat(ex.getMessage()).isEqualTo("missing client token");
    }

    @Test
    void fromResponse_403_permissionDenied() {
        String body = "{\"errors\":[\"permission denied\"]}";
        VaultException ex = VaultException.fromResponse(403, body);

        assertThat(ex.getHttpStatusCode()).isEqualTo(403);
        assertThat(ex.getMessage()).isEqualTo("permission denied");
    }

    @Test
    void fromResponse_404_notFound() {
        String body = "{\"errors\":[]}";  // Vault often returns empty errors for 404
        VaultException ex = VaultException.fromResponse(404, body);

        assertThat(ex.getHttpStatusCode()).isEqualTo(404);
    }

    @Test
    void fromResponse_500_internalError() {
        String body = "{\"errors\":[\"internal error\"]}";
        VaultException ex = VaultException.fromResponse(500, body);

        assertThat(ex.getHttpStatusCode()).isEqualTo(500);
        assertThat(ex.getMessage()).isEqualTo("internal error");
    }

    @Test
    void fromResponse_503_serviceUnavailable() {
        String body = "{\"errors\":[\"Vault is sealed\"]}";
        VaultException ex = VaultException.fromResponse(503, body);

        assertThat(ex.getHttpStatusCode()).isEqualTo(503);
        assertThat(ex.getMessage()).isEqualTo("Vault is sealed");
    }
}
