package com.hashicorp.vault.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for TokenAuthenticator.
 */
class TokenAuthenticatorTest {

    @TempDir
    Path tempDir;

    @Test
    void constructor_withValidToken_succeeds() {
        TokenAuthenticator auth = new TokenAuthenticator("hvs.test-token", "test source");

        assertThat(auth.getAuthMethod()).isEqualTo(AuthMethod.TOKEN);
        assertThat(auth.getTokenSource()).isEqualTo("test source");
    }

    @Test
    void constructor_withNullToken_throwsException() {
        assertThatThrownBy(() -> new TokenAuthenticator(null, "source"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or blank");
    }

    @Test
    void constructor_withBlankToken_throwsException() {
        assertThatThrownBy(() -> new TokenAuthenticator("   ", "source"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or blank");
    }

    @Test
    void fromFile_withValidFile_readsToken() throws Exception {
        Path tokenFile = tempDir.resolve("token");
        Files.writeString(tokenFile, "hvs.file-token\n");

        TokenAuthenticator auth = TokenAuthenticator.create(null,tokenFile.toString());

        assertThat(auth.getTokenSource()).contains(tokenFile.toString());
    }

    @Test
    void fromFile_withEmptyFile_throwsException() throws Exception {
        Path tokenFile = tempDir.resolve("empty-token");
        Files.writeString(tokenFile, "   ");

        assertThatThrownBy(() -> TokenAuthenticator.create(null,tokenFile.toString()))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void fromFile_withNonexistentFile_throwsException() {
        assertThatThrownBy(() -> TokenAuthenticator.create(null,"/nonexistent/path"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Cannot read");
    }

    @Test
    void authenticate_setsTokenOnClient() {
        TokenAuthenticator auth = new TokenAuthenticator("hvs.test", "test");
        VaultHttpClient mockClient = mock(VaultHttpClient.class);

        auth.authenticate(mockClient);

        verify(mockClient).setToken("hvs.test");
    }

    @Test
    void supportsReauthentication_returnsFalse() {
        TokenAuthenticator auth = new TokenAuthenticator("hvs.test", "test");

        assertThat(auth.supportsReauthentication()).isFalse();
    }

    @Test
    void reauthenticate_throwsUnsupportedOperationException() {
        TokenAuthenticator auth = new TokenAuthenticator("hvs.test", "test");
        VaultHttpClient mockClient = mock(VaultHttpClient.class);

        assertThatThrownBy(() -> auth.reauthenticate(mockClient))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("does not support re-authentication");
    }

    @Test
    void fromFile_trimsWhitespace() throws Exception {
        Path tokenFile = tempDir.resolve("token-with-whitespace");
        Files.writeString(tokenFile, "  hvs.trimmed-token  \n\n");

        TokenAuthenticator auth = TokenAuthenticator.create(null,tokenFile.toString());
        VaultHttpClient mockClient = mock(VaultHttpClient.class);

        auth.authenticate(mockClient);

        verify(mockClient).setToken("hvs.trimmed-token");
    }
}
