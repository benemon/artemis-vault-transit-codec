package com.hashicorp.vault.client;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import javax.net.ssl.SSLContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lightweight HTTP client wrapper for HashiCorp Vault REST API.
 *
 * <p>This class provides a thin wrapper around {@link HttpClient} for making
 * authenticated requests to Vault. It handles:
 * <ul>
 *   <li>Token-based authentication via X-Vault-Token header</li>
 *   <li>Namespace support via X-Vault-Namespace header (Vault Enterprise)</li>
 *   <li>Request/response JSON serialization</li>
 *   <li>Error response parsing</li>
 * </ul>
 *
 * <p>The client is designed to be injectable/mockable for unit testing.
 */
public class VaultHttpClient {

    private static final Logger logger = LoggerFactory.getLogger(VaultHttpClient.class);

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final String HEADER_VAULT_TOKEN = "X-Vault-Token";
    private static final String HEADER_VAULT_NAMESPACE = "X-Vault-Namespace";
    private static final String CONTENT_TYPE_JSON = "application/json";

    private final HttpClient httpClient;
    private final String baseUrl;
    private volatile String token;
    private String namespace;
    private final Duration requestTimeout;

    /**
     * Creates a new VaultHttpClient with default settings.
     *
     * @param baseUrl the Vault server URL (e.g., "https://vault:8200")
     */
    public VaultHttpClient(String baseUrl) {
        this(baseUrl, null, null, null);
    }

    /**
     * Creates a new VaultHttpClient with custom SSL context.
     *
     * @param baseUrl    the Vault server URL
     * @param sslContext custom SSL context for TLS configuration, or null for default
     * @param namespace  Vault namespace (Enterprise), or null for root namespace
     * @param token      initial Vault token, or null if authenticating later
     */
    public VaultHttpClient(String baseUrl, SSLContext sslContext, String namespace, String token) {
        this(buildHttpClient(sslContext), baseUrl, namespace, token, DEFAULT_REQUEST_TIMEOUT);
    }

    /**
     * Creates a new VaultHttpClient with an injected HttpClient (for testing).
     *
     * @param httpClient     the HTTP client to use
     * @param baseUrl        the Vault server URL
     * @param namespace      Vault namespace, or null
     * @param token          Vault token, or null
     * @param requestTimeout timeout for individual requests
     */
    public VaultHttpClient(HttpClient httpClient, String baseUrl, String namespace,
                           String token, Duration requestTimeout) {
        this.httpClient = httpClient;
        this.baseUrl = normalizeUrl(baseUrl);
        this.namespace = namespace;
        this.token = token;
        this.requestTimeout = requestTimeout != null ? requestTimeout : DEFAULT_REQUEST_TIMEOUT;
    }

    private static HttpClient buildHttpClient(SSLContext sslContext) {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(DEFAULT_CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NORMAL);

        if (sslContext != null) {
            builder.sslContext(sslContext);
        }

        return builder.build();
    }

    private static String normalizeUrl(String url) {
        // Remove trailing slash for consistent URL building
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public VaultResponse get(String path) throws VaultException {
        return get(path, null);
    }

    public VaultResponse get(String path, String namespaceOverride) throws VaultException {
        HttpRequest request = buildRequest(path, namespaceOverride).GET().build();
        return execute(request);
    }

    public VaultResponse post(String path, Map<String, Object> body) throws VaultException {
        return post(path, body, null);
    }

    public VaultResponse post(String path, Map<String, Object> body, String namespaceOverride)
            throws VaultException {
        String jsonBody = body != null ? JsonUtil.toJson(body) : "{}";
        HttpRequest request = buildRequest(path, namespaceOverride)
                .header("Content-Type", CONTENT_TYPE_JSON)
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();
        return execute(request);
    }

    /** POST without authentication (for AppRole login). */
    public VaultResponse postUnauthenticated(String path, Map<String, Object> body)
            throws VaultException {
        String jsonBody = body != null ? JsonUtil.toJson(body) : "{}";

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(requestTimeout)
                .header("Content-Type", CONTENT_TYPE_JSON);

        if (namespace != null && !namespace.isBlank()) {
            builder.header(HEADER_VAULT_NAMESPACE, namespace);
        }

        return execute(builder.POST(HttpRequest.BodyPublishers.ofString(jsonBody)).build());
    }

    private HttpRequest.Builder buildRequest(String path, String namespaceOverride) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(requestTimeout);

        String currentToken = this.token;
        if (currentToken != null && !currentToken.isBlank()) {
            builder.header(HEADER_VAULT_TOKEN, currentToken);
        }

        String ns = namespaceOverride != null ? namespaceOverride : namespace;
        if (ns != null && !ns.isBlank()) {
            builder.header(HEADER_VAULT_NAMESPACE, ns);
        }

        return builder;
    }

    private VaultResponse execute(HttpRequest request) throws VaultException {
        logger.debug("Vault request: {} {}", request.method(), request.uri());

        try {
            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString());

            int status = response.statusCode();
            String body = response.body();

            logger.debug("Vault response: {} ({})", status,
                    body != null ? body.length() + " bytes" : "empty");

            if (status >= 400) {
                throw VaultException.fromResponse(status, body);
            }

            return VaultResponse.fromJson(status, body);

        } catch (IOException e) {
            // Connection errors get status 0 (matches vault-java-driver behavior)
            throw new VaultException("Connection failed: " + e.getMessage(), 0, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VaultException("Request interrupted", 0, e);
        }
    }

    /** Authenticates using AppRole and returns the client token. */
    public String loginAppRole(String roleId, String secretId) throws VaultException {
        VaultResponse response = postUnauthenticated("/v1/auth/approle/login",
                Map.of("role_id", roleId, "secret_id", secretId));

        Map<String, Object> auth = response.getAuth();
        if (auth == null) {
            throw new VaultException("AppRole login response missing 'auth' field",
                    response.getStatus());
        }

        String clientToken = (String) auth.get("client_token");
        if (clientToken == null || clientToken.isBlank()) {
            throw new VaultException("AppRole login response missing 'client_token'",
                    response.getStatus());
        }

        return clientToken;
    }

    /** Looks up the current token's metadata (TTL, policies, etc.). */
    public VaultResponse lookupSelf() throws VaultException {
        return get("/v1/auth/token/lookup-self");
    }

    /** Renews the current token. */
    public void renewSelf() throws VaultException {
        post("/v1/auth/token/renew-self", Map.of());
    }

    /** Encrypts base64-encoded plaintext using Transit, returns ciphertext (vault:v{N}:...). */
    public String transitEncrypt(String mount, String keyName, String base64Plaintext,
                                  String namespaceOverride) throws VaultException {
        String path = "/v1/" + mount + "/encrypt/" + keyName;
        VaultResponse response = post(path, Map.of("plaintext", base64Plaintext), namespaceOverride);

        Map<String, Object> data = response.getData();
        if (data == null) {
            throw new VaultException("Transit encrypt response missing 'data' field",
                    response.getStatus());
        }

        String ciphertext = (String) data.get("ciphertext");
        if (ciphertext == null) {
            throw new VaultException("Transit encrypt response missing 'ciphertext'",
                    response.getStatus());
        }

        return ciphertext;
    }

    /** Decrypts Transit ciphertext, returns base64-encoded plaintext. */
    public String transitDecrypt(String mount, String keyName, String ciphertext,
                                  String namespaceOverride) throws VaultException {
        String path = "/v1/" + mount + "/decrypt/" + keyName;
        VaultResponse response = post(path, Map.of("ciphertext", ciphertext), namespaceOverride);

        Map<String, Object> data = response.getData();
        if (data == null) {
            throw new VaultException("Transit decrypt response missing 'data' field",
                    response.getStatus());
        }

        String plaintext = (String) data.get("plaintext");
        if (plaintext == null) {
            throw new VaultException("Transit decrypt response missing 'plaintext'",
                    response.getStatus());
        }

        return plaintext;
    }

    /** Reads Transit key metadata. */
    public VaultResponse transitReadKey(String mount, String keyName, String namespaceOverride)
            throws VaultException {
        String path = "/v1/" + mount + "/keys/" + keyName;
        return get(path, namespaceOverride);
    }

    public String getBaseUrl() {
        return baseUrl;
    }
}
