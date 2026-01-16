package com.hashicorp.vault.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for AppRoleAuthenticator.
 */
class AppRoleAuthenticatorTest {

    @TempDir
    Path tempDir;

    @Test
    void constructor_withDirectSecretId_succeeds() {
        AppRoleAuthenticator auth = new AppRoleAuthenticator(
                "role-123", "secret-456", "test source");

        assertThat(auth.getAuthMethod()).isEqualTo("approle");
        assertThat(auth.getRoleId()).isEqualTo("role-123");
        assertThat(auth.getSecretSource()).isEqualTo("test source");
    }

    @Test
    void constructor_withNullRoleId_throwsException() {
        assertThatThrownBy(() -> new AppRoleAuthenticator(null, "secret", "source"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Role ID");
    }

    @Test
    void constructor_withNullSecretId_throwsException() {
        assertThatThrownBy(() -> new AppRoleAuthenticator("role", null, "source"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Secret ID");
    }

    @Test
    void constructorWithFile_withValidFile_succeeds() throws Exception {
        Path secretFile = tempDir.resolve("secret");
        Files.writeString(secretFile, "secret-from-file");

        AppRoleAuthenticator auth = new AppRoleAuthenticator("role-123", secretFile.toString());

        assertThat(auth.getAuthMethod()).isEqualTo("approle");
        assertThat(auth.getRoleId()).isEqualTo("role-123");
        assertThat(auth.getSecretSource()).contains(secretFile.toString());
    }

    @Test
    void constructorWithFile_withNullPath_throwsException() {
        assertThatThrownBy(() -> new AppRoleAuthenticator("role", (String) null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Secret file path");
    }

    @Test
    void supportsReauthentication_withDirectSecret_returnsFalse() {
        AppRoleAuthenticator auth = new AppRoleAuthenticator(
                "role", "secret", "source");

        assertThat(auth.supportsReauthentication()).isFalse();
    }

    @Test
    void supportsReauthentication_withSecretFile_returnsTrue() throws Exception {
        Path secretFile = tempDir.resolve("secret");
        Files.writeString(secretFile, "secret");

        AppRoleAuthenticator auth = new AppRoleAuthenticator("role", secretFile.toString());

        assertThat(auth.supportsReauthentication()).isTrue();
    }

    @Test
    void authenticate_withDirectSecret_logsInAndSetsToken() throws Exception {
        AppRoleAuthenticator auth = new AppRoleAuthenticator(
                "role-123", "secret-456", "test");

        VaultHttpClient mockClient = mock(VaultHttpClient.class);
        when(mockClient.loginAppRole("role-123", "secret-456"))
                .thenReturn("hvs.new-token");

        auth.authenticate(mockClient);

        verify(mockClient).loginAppRole("role-123", "secret-456");
        verify(mockClient).setToken("hvs.new-token");
    }

    @Test
    void authenticate_withSecretFile_readsFileAndLogsIn() throws Exception {
        Path secretFile = tempDir.resolve("secret");
        Files.writeString(secretFile, "file-secret-123\n");

        AppRoleAuthenticator auth = new AppRoleAuthenticator("role-id", secretFile.toString());

        VaultHttpClient mockClient = mock(VaultHttpClient.class);
        when(mockClient.loginAppRole("role-id", "file-secret-123"))
                .thenReturn("hvs.token");

        auth.authenticate(mockClient);

        verify(mockClient).loginAppRole("role-id", "file-secret-123");
        verify(mockClient).setToken("hvs.token");
    }

    @Test
    void reauthenticate_withSecretFile_reReadsFileAndLogsIn() throws Exception {
        Path secretFile = tempDir.resolve("secret");
        Files.writeString(secretFile, "initial-secret");

        AppRoleAuthenticator auth = new AppRoleAuthenticator("role-id", secretFile.toString());

        VaultHttpClient mockClient = mock(VaultHttpClient.class);
        when(mockClient.loginAppRole(anyString(), anyString()))
                .thenReturn("hvs.token");

        // Initial auth
        auth.authenticate(mockClient);
        verify(mockClient).loginAppRole("role-id", "initial-secret");

        // Simulate secret rotation
        Files.writeString(secretFile, "rotated-secret");

        // Re-authenticate
        auth.reauthenticate(mockClient);
        verify(mockClient).loginAppRole("role-id", "rotated-secret");
        verify(mockClient, times(2)).setToken("hvs.token");
    }

    @Test
    void reauthenticate_withStaticSecret_throwsUnsupportedOperationException() {
        // Static secrets (passed directly, not from file or env var) don't support re-auth
        AppRoleAuthenticator auth = new AppRoleAuthenticator(
                "role", "secret", "static source");

        VaultHttpClient mockClient = mock(VaultHttpClient.class);

        assertThatThrownBy(() -> auth.reauthenticate(mockClient))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("requires a dynamic secret source");
    }

    @Test
    void authenticate_withVaultError_throwsSecurityException() throws Exception {
        AppRoleAuthenticator auth = new AppRoleAuthenticator(
                "role", "bad-secret", "test");

        VaultHttpClient mockClient = mock(VaultHttpClient.class);
        when(mockClient.loginAppRole("role", "bad-secret"))
                .thenThrow(new VaultException("invalid credentials", 401));

        assertThatThrownBy(() -> auth.authenticate(mockClient))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("failed");
    }

    @Test
    void reauthenticate_withEmptySecretFile_throwsSecurityException() throws Exception {
        Path secretFile = tempDir.resolve("secret");
        Files.writeString(secretFile, "initial");

        AppRoleAuthenticator auth = new AppRoleAuthenticator("role", secretFile.toString());

        // Empty the file after construction
        Files.writeString(secretFile, "   ");

        VaultHttpClient mockClient = mock(VaultHttpClient.class);

        assertThatThrownBy(() -> auth.reauthenticate(mockClient))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void reauthenticate_withMissingSecretFile_throwsSecurityException() throws Exception {
        Path secretFile = tempDir.resolve("secret");
        Files.writeString(secretFile, "initial");

        AppRoleAuthenticator auth = new AppRoleAuthenticator("role", secretFile.toString());

        // Delete the file after construction
        Files.delete(secretFile);

        VaultHttpClient mockClient = mock(VaultHttpClient.class);

        assertThatThrownBy(() -> auth.reauthenticate(mockClient))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Cannot read");
    }

    @Test
    void authenticate_trimsWhitespaceFromSecretFile() throws Exception {
        Path secretFile = tempDir.resolve("secret");
        Files.writeString(secretFile, "  secret-with-whitespace  \n\n");

        AppRoleAuthenticator auth = new AppRoleAuthenticator("role", secretFile.toString());

        VaultHttpClient mockClient = mock(VaultHttpClient.class);
        when(mockClient.loginAppRole("role", "secret-with-whitespace"))
                .thenReturn("hvs.token");

        auth.authenticate(mockClient);

        verify(mockClient).loginAppRole("role", "secret-with-whitespace");
    }
}
