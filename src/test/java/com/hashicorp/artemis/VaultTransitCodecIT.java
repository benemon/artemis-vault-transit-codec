package com.hashicorp.artemis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.vault.VaultContainer;

/**
 * Integration tests for VaultTransitCodec using Testcontainers with a real Vault server.
 */
@Testcontainers
class VaultTransitCodecIT {

    private static final String ROOT_TOKEN = "root-test-token";
    private static final String TRANSIT_KEY = "test-key";
    private static final String VAULT_VERSION = System.getenv("VAULT_TEST_VERSION") != null
            ? System.getenv("VAULT_TEST_VERSION")
            : "1.21";

    @Container
    static VaultContainer<?> vaultContainer = new VaultContainer<>("hashicorp/vault:" + VAULT_VERSION)
            .withVaultToken(ROOT_TOKEN)
            .withInitCommand(
                    "secrets enable transit",
                    "write -f transit/keys/" + TRANSIT_KEY
            );

    @TempDir
    Path tempDir;

    private VaultTransitCodec codec;
    private String vaultAddr;

    @BeforeEach
    void setUp() {
        codec = new VaultTransitCodec();
        vaultAddr = "http://" + vaultContainer.getHost() + ":" + vaultContainer.getFirstMappedPort();
    }

    // --- Basic functionality tests ---

    @Test
    void roundTrip_encodeDecode_returnsOriginal() throws Exception {
        initCodecWithToken();

        String original = "my-secret-password";
        String encoded = codec.encode(original);
        String decoded = codec.decode(encoded);

        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void roundTrip_withSpecialCharacters_succeeds() throws Exception {
        initCodecWithToken();

        String original = "p@$$w0rd!#$%^&*()_+-=[]{}|;':\",./<>?`~\n\ttab";
        String encoded = codec.encode(original);
        String decoded = codec.decode(encoded);

        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void roundTrip_withUnicode_succeeds() throws Exception {
        initCodecWithToken();

        String original = "密码пароль🔐";
        String encoded = codec.encode(original);
        String decoded = codec.decode(encoded);

        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void roundTrip_withEmptyString_succeeds() throws Exception {
        initCodecWithToken();

        String original = "";
        String encoded = codec.encode(original);
        String decoded = codec.decode(encoded);

        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void encode_returnsCiphertextWithVaultPrefix() throws Exception {
        initCodecWithToken();

        String encoded = codec.encode("password");

        assertThat(encoded).startsWith("vault:v");
        assertThat(encoded).contains(":");
    }

    @Test
    void encode_isNonDeterministic() throws Exception {
        initCodecWithToken();

        String encoded1 = codec.encode("password");
        String encoded2 = codec.encode("password");

        // Same plaintext produces different ciphertext each time
        // (Vault Transit uses convergent encryption by default, but key version may differ)
        // Actually, Vault Transit without convergent_encryption produces different ciphertext
        assertThat(encoded1).isNotEqualTo(encoded2);
    }

    // --- Verify tests ---

    @Test
    void verify_withCorrectPassword_returnsTrue() throws Exception {
        initCodecWithToken();

        String encoded = codec.encode("correct-password");
        boolean result = codec.verify("correct-password".toCharArray(), encoded);

        assertThat(result).isTrue();
    }

    @Test
    void verify_withWrongPassword_returnsFalse() throws Exception {
        initCodecWithToken();

        String encoded = codec.encode("correct-password");
        boolean result = codec.verify("wrong-password".toCharArray(), encoded);

        assertThat(result).isFalse();
    }

    @Test
    void verify_withInvalidCiphertext_returnsFalseNotException() throws Exception {
        initCodecWithToken();

        boolean result = codec.verify("password".toCharArray(), "invalid-ciphertext");

        assertThat(result).isFalse();
    }

    // --- Token authentication tests ---

    @Test
    void tokenAuth_withTokenFile_succeeds() throws Exception {
        Path tokenFile = tempDir.resolve("vault-token");
        Files.writeString(tokenFile, ROOT_TOKEN);

        Map<String, String> params = Map.of(
                "vault-addr", vaultAddr,
                "transit-key", TRANSIT_KEY,
                "token-path", tokenFile.toString()
        );

        codec.init(params);

        // Should be able to encode/decode
        String encoded = codec.encode("token-file-test");
        String decoded = codec.decode(encoded);
        assertThat(decoded).isEqualTo("token-file-test");
    }

    // --- Custom transit mount tests ---

    @Test
    void customTransitMount_roundTrip_succeeds() throws Exception {
        // Enable Transit at a custom path
        String customMount = "custom-transit";
        String customKey = "custom-key";

        vaultContainer.execInContainer("vault", "secrets", "enable", "-path=" + customMount, "transit");
        vaultContainer.execInContainer("vault", "write", "-f", customMount + "/keys/" + customKey);

        Path tokenFile = tempDir.resolve("vault-token");
        Files.writeString(tokenFile, ROOT_TOKEN);

        Map<String, String> params = Map.of(
                "vault-addr", vaultAddr,
                "transit-mount", customMount,
                "transit-key", customKey,
                "token-path", tokenFile.toString()
        );

        codec.init(params);

        String original = "custom-mount-password";
        String encoded = codec.encode(original);
        String decoded = codec.decode(encoded);

        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void customTransitMount_withNestedPath_succeeds() throws Exception {
        // Enable Transit at a nested path (common in multi-tenant setups)
        String nestedMount = "secrets/team-a/transit";
        String customKey = "team-key";

        vaultContainer.execInContainer("vault", "secrets", "enable",
                "-path=" + nestedMount, "transit");
        vaultContainer.execInContainer("vault", "write", "-f",
                nestedMount + "/keys/" + customKey);

        Path tokenFile = tempDir.resolve("vault-token");
        Files.writeString(tokenFile, ROOT_TOKEN);

        Map<String, String> params = Map.of(
                "vault-addr", vaultAddr,
                "transit-mount", nestedMount,
                "transit-key", customKey,
                "token-path", tokenFile.toString()
        );

        codec.init(params);

        String original = "nested-path-password";
        String encoded = codec.encode(original);
        String decoded = codec.decode(encoded);

        assertThat(decoded).isEqualTo(original);
    }

    // --- AppRole authentication tests ---

    @Test
    void appRoleAuth_withSecretFile_succeeds() throws Exception {
        // Create a policy that grants transit access
        vaultContainer.execInContainer("sh", "-c",
                "echo 'path \"transit/*\" { capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"] }' | vault policy write transit-policy -");

        // Enable AppRole and create role with our policy
        vaultContainer.execInContainer("vault", "auth", "enable", "approle");
        vaultContainer.execInContainer("vault", "write", "auth/approle/role/test-role",
                "token_policies=transit-policy",
                "token_ttl=1h");

        // Get role ID
        var roleIdResult = vaultContainer.execInContainer("vault", "read", "-field=role_id",
                "auth/approle/role/test-role/role-id");
        String roleId = roleIdResult.getStdout().trim();

        // Get secret ID
        var secretIdResult = vaultContainer.execInContainer("vault", "write", "-field=secret_id", "-f",
                "auth/approle/role/test-role/secret-id");
        String secretId = secretIdResult.getStdout().trim();

        // Create secret file
        Path secretFile = tempDir.resolve("secret-id");
        Files.writeString(secretFile, secretId);

        Map<String, String> params = Map.of(
                "vault-addr", vaultAddr,
                "transit-key", TRANSIT_KEY,
                "auth-method", "approle",
                "approle-id", roleId,
                "approle-secret-file", secretFile.toString()
        );

        codec.init(params);

        // Should be able to encode/decode
        String encoded = codec.encode("approle-test");
        String decoded = codec.decode(encoded);
        assertThat(decoded).isEqualTo("approle-test");
    }

    // --- Cache tests ---

    @Test
    void decode_cacheHit_doesNotCallVaultAgain() throws Exception {
        initCodecWithToken();

        String encoded = codec.encode("cached-password");

        // First decode - cache miss
        String decoded1 = codec.decode(encoded);
        // Second decode - should be cache hit
        String decoded2 = codec.decode(encoded);

        assertThat(decoded1).isEqualTo("cached-password");
        assertThat(decoded2).isEqualTo("cached-password");

        // Verify cache has entry
        assertThat(codec.getCache()).containsKey(encoded);
    }

    @Test
    void decode_withCacheDisabled_alwaysCallsVault() throws Exception {
        Path tokenFile = tempDir.resolve("vault-token");
        Files.writeString(tokenFile, ROOT_TOKEN);

        Map<String, String> params = Map.of(
                "vault-addr", vaultAddr,
                "transit-key", TRANSIT_KEY,
                "token-path", tokenFile.toString(),
                "cache-ttl-seconds", "0"
        );

        codec.init(params);

        String encoded = codec.encode("uncached-password");

        codec.decode(encoded);
        codec.decode(encoded);

        // Cache should be null when disabled
        assertThat(codec.getCache()).isNull();
    }

    // --- Thread safety tests ---

    @Test
    void decode_threadSafety_concurrentCalls() throws Exception {
        initCodecWithToken();

        String encoded = codec.encode("concurrent-password");

        int threadCount = 10;
        int iterationsPerThread = 50;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicInteger failures = new AtomicInteger(0);
        List<Exception> exceptions = new CopyOnWriteArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await(); // Wait for all threads to be ready
                    for (int j = 0; j < iterationsPerThread; j++) {
                        String result = codec.decode(encoded);
                        if (!"concurrent-password".equals(result)) {
                            failures.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    exceptions.add(e);
                    failures.incrementAndGet();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // Start all threads simultaneously
        boolean completed = doneLatch.await(60, TimeUnit.SECONDS);

        executor.shutdownNow();

        assertThat(completed).isTrue();
        assertThat(failures.get()).isZero();
        assertThat(exceptions).isEmpty();
    }

    @Test
    void encode_threadSafety_concurrentCalls() throws Exception {
        initCodecWithToken();

        int threadCount = 10;
        int iterationsPerThread = 20;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicInteger failures = new AtomicInteger(0);
        List<String> encodedValues = new CopyOnWriteArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            final int threadNum = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < iterationsPerThread; j++) {
                        String plaintext = "password-" + threadNum + "-" + j;
                        String encoded = codec.encode(plaintext);
                        String decoded = codec.decode(encoded);
                        if (!plaintext.equals(decoded)) {
                            failures.incrementAndGet();
                        }
                        encodedValues.add(encoded);
                    }
                } catch (Exception e) {
                    failures.incrementAndGet();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = doneLatch.await(60, TimeUnit.SECONDS);

        executor.shutdownNow();

        assertThat(completed).isTrue();
        assertThat(failures.get()).isZero();
        assertThat(encodedValues).hasSize(threadCount * iterationsPerThread);
    }

    // --- Multiple passwords test ---

    @Test
    void multiplePasswords_allDecodeCorrectly() throws Exception {
        initCodecWithToken();

        List<String> passwords = List.of(
                "admin-password",
                "cluster-password",
                "connector-password",
                "acceptor-password",
                "bridge-password"
        );

        List<String> encodedPasswords = new ArrayList<>();
        for (String password : passwords) {
            encodedPasswords.add(codec.encode(password));
        }

        // Decode in different order
        for (int i = passwords.size() - 1; i >= 0; i--) {
            String decoded = codec.decode(encodedPasswords.get(i));
            assertThat(decoded).isEqualTo(passwords.get(i));
        }
    }

    // --- Error handling tests ---

    @Test
    void decode_withInvalidCiphertext_throwsException() throws Exception {
        initCodecWithToken();

        // Valid format but not actually encrypted by our key
        assertThatThrownBy(() -> codec.decode("vault:v1:invalidciphertext"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void init_withNonexistentTransitKey_throwsException() {
        Path tokenFile = tempDir.resolve("vault-token");
        try {
            Files.writeString(tokenFile, ROOT_TOKEN);
        } catch (Exception e) {
            fail("Failed to create token file", e);
        }

        Map<String, String> params = Map.of(
                "vault-addr", vaultAddr,
                "transit-key", "nonexistent-key",
                "token-path", tokenFile.toString()
        );

        assertThatThrownBy(() -> codec.init(params))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("nonexistent-key");
    }

    @Test
    void init_withInvalidVaultAddr_throwsException() {
        Path tokenFile = tempDir.resolve("vault-token");
        try {
            Files.writeString(tokenFile, ROOT_TOKEN);
        } catch (Exception e) {
            fail("Failed to create token file", e);
        }

        Map<String, String> params = Map.of(
                "vault-addr", "http://nonexistent-host:8200",
                "transit-key", TRANSIT_KEY,
                "token-path", tokenFile.toString()
        );

        assertThatThrownBy(() -> codec.init(params))
                .isInstanceOf(Exception.class);
    }

    // --- Helper methods ---

    private void initCodecWithToken() throws Exception {
        Path tokenFile = tempDir.resolve("vault-token");
        Files.writeString(tokenFile, ROOT_TOKEN);

        Map<String, String> params = Map.of(
                "vault-addr", vaultAddr,
                "transit-key", TRANSIT_KEY,
                "token-path", tokenFile.toString()
        );

        codec.init(params);
    }
}
