package com.hashicorp.vault.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for JsonUtil JSON serialization and parsing.
 */
class JsonUtilTest {

    // --- toJson tests ---

    @Test
    void toJson_withNull_returnsEmptyObject() {
        String result = JsonUtil.toJson(null);
        assertThat(result).isEqualTo("{}");
    }

    @Test
    void toJson_withEmptyMap_returnsEmptyObject() {
        String result = JsonUtil.toJson(Map.of());
        assertThat(result).isEqualTo("{}");
    }

    @Test
    void toJson_withStringValue_returnsValidJson() {
        String result = JsonUtil.toJson(Map.of("key", "value"));
        assertThat(result).isEqualTo("{\"key\":\"value\"}");
    }

    @Test
    void toJson_withIntegerValue_returnsValidJson() {
        String result = JsonUtil.toJson(Map.of("count", 42));
        assertThat(result).isEqualTo("{\"count\":42}");
    }

    @Test
    void toJson_withBooleanValue_returnsValidJson() {
        String result = JsonUtil.toJson(Map.of("enabled", true));
        assertThat(result).isEqualTo("{\"enabled\":true}");
    }

    @Test
    void toJson_withNullValue_returnsNull() {
        Map<String, Object> map = new java.util.HashMap<>();
        map.put("key", null);
        String result = JsonUtil.toJson(map);
        assertThat(result).isEqualTo("{\"key\":null}");
    }

    @Test
    void toJson_withSpecialCharacters_escapesCorrectly() {
        String result = JsonUtil.toJson(Map.of("text", "line1\nline2\ttab\"quote\\backslash"));
        assertThat(result).contains("\\n").contains("\\t").contains("\\\"").contains("\\\\");
    }

    @Test
    void toJson_withNestedMap_serializesCorrectly() {
        Map<String, Object> nested = Map.of("inner", "value");
        String result = JsonUtil.toJson(Map.of("outer", nested));
        assertThat(result).isEqualTo("{\"outer\":{\"inner\":\"value\"}}");
    }

    @Test
    void toJson_withList_serializesCorrectly() {
        String result = JsonUtil.toJson(Map.of("items", List.of("a", "b", "c")));
        assertThat(result).isEqualTo("{\"items\":[\"a\",\"b\",\"c\"]}");
    }

    // --- parseObject tests ---

    @Test
    void parseObject_withNull_returnsNull() {
        Map<String, Object> result = JsonUtil.parseObject(null);
        assertThat(result).isNull();
    }

    @Test
    void parseObject_withEmptyString_returnsNull() {
        Map<String, Object> result = JsonUtil.parseObject("");
        assertThat(result).isNull();
    }

    @Test
    void parseObject_withBlankString_returnsNull() {
        Map<String, Object> result = JsonUtil.parseObject("   ");
        assertThat(result).isNull();
    }

    @Test
    void parseObject_withEmptyObject_returnsEmptyMap() {
        Map<String, Object> result = JsonUtil.parseObject("{}");
        assertThat(result).isNotNull().isEmpty();
    }

    @Test
    void parseObject_withStringValue_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"key\":\"value\"}");
        assertThat(result).containsEntry("key", "value");
    }

    @Test
    void parseObject_withIntegerValue_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"count\":42}");
        assertThat(result).containsEntry("count", 42);
    }

    @Test
    void parseObject_withLongValue_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"big\":9999999999}");
        assertThat(result).containsEntry("big", 9999999999L);
    }

    @Test
    void parseObject_withDoubleValue_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"pi\":3.14159}");
        assertThat(result.get("pi")).isInstanceOf(Double.class);
        assertThat((Double) result.get("pi")).isCloseTo(3.14159, within(0.00001));
    }

    @Test
    void parseObject_withBooleanTrue_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"enabled\":true}");
        assertThat(result).containsEntry("enabled", true);
    }

    @Test
    void parseObject_withBooleanFalse_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"enabled\":false}");
        assertThat(result).containsEntry("enabled", false);
    }

    @Test
    void parseObject_withNullValue_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"value\":null}");
        assertThat(result).containsKey("value");
        assertThat(result.get("value")).isNull();
    }

    @Test
    void parseObject_withNestedObject_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"data\":{\"ciphertext\":\"vault:v1:abc\"}}");
        assertThat(result).containsKey("data");
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        assertThat(data).containsEntry("ciphertext", "vault:v1:abc");
    }

    @Test
    void parseObject_withArray_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"errors\":[\"error1\",\"error2\"]}");
        assertThat(result).containsKey("errors");
        @SuppressWarnings("unchecked")
        List<Object> errors = (List<Object>) result.get("errors");
        assertThat(errors).containsExactly("error1", "error2");
    }

    @Test
    void parseObject_withWhitespace_parsesCorrectly() {
        String json = """
                {
                    "key" : "value" ,
                    "number" : 42
                }
                """;
        Map<String, Object> result = JsonUtil.parseObject(json);
        assertThat(result).containsEntry("key", "value").containsEntry("number", 42);
    }

    @Test
    void parseObject_withEscapedStrings_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"text\":\"line1\\nline2\\ttab\"}");
        assertThat(result.get("text")).isEqualTo("line1\nline2\ttab");
    }

    @Test
    void parseObject_withUnicodeEscape_parsesCorrectly() {
        Map<String, Object> result = JsonUtil.parseObject("{\"text\":\"\\u0048\\u0065\\u006c\\u006c\\u006f\"}");
        assertThat(result.get("text")).isEqualTo("Hello");
    }

    @Test
    void parseObject_withInvalidJson_returnsNull() {
        Map<String, Object> result = JsonUtil.parseObject("not json");
        assertThat(result).isNull();
    }

    @Test
    void parseObject_withIncompleteJson_returnsNull() {
        Map<String, Object> result = JsonUtil.parseObject("{\"key\":\"value\"");
        assertThat(result).isNull();
    }

    // --- parseErrors tests ---

    @Test
    void parseErrors_withNull_returnsNull() {
        List<String> result = JsonUtil.parseErrors(null);
        assertThat(result).isNull();
    }

    @Test
    void parseErrors_withEmptyString_returnsNull() {
        List<String> result = JsonUtil.parseErrors("");
        assertThat(result).isNull();
    }

    @Test
    void parseErrors_withNoErrorsField_returnsNull() {
        List<String> result = JsonUtil.parseErrors("{\"data\":{}}");
        assertThat(result).isNull();
    }

    @Test
    void parseErrors_withSingleError_returnsList() {
        List<String> result = JsonUtil.parseErrors("{\"errors\":[\"permission denied\"]}");
        assertThat(result).containsExactly("permission denied");
    }

    @Test
    void parseErrors_withMultipleErrors_returnsList() {
        List<String> result = JsonUtil.parseErrors("{\"errors\":[\"error1\",\"error2\",\"error3\"]}");
        assertThat(result).containsExactly("error1", "error2", "error3");
    }

    @Test
    void parseErrors_withEmptyErrorsArray_returnsEmptyList() {
        List<String> result = JsonUtil.parseErrors("{\"errors\":[]}");
        assertThat(result).isEmpty();
    }

    @Test
    void parseErrors_withNullInArray_skipsNull() {
        List<String> result = JsonUtil.parseErrors("{\"errors\":[\"error1\",null,\"error2\"]}");
        assertThat(result).containsExactly("error1", "error2");
    }

    // --- Roundtrip tests ---

    @Test
    void roundtrip_simpleMap_preservesData() {
        Map<String, Object> original = Map.of(
                "string", "hello",
                "number", 42,
                "bool", true
        );

        String json = JsonUtil.toJson(original);
        Map<String, Object> parsed = JsonUtil.parseObject(json);

        assertThat(parsed).containsEntry("string", "hello");
        assertThat(parsed).containsEntry("number", 42);
        assertThat(parsed).containsEntry("bool", true);
    }

    @Test
    void roundtrip_vaultEncryptRequest_preservesData() {
        Map<String, Object> request = Map.of("plaintext", "dGVzdA==");
        String json = JsonUtil.toJson(request);
        Map<String, Object> parsed = JsonUtil.parseObject(json);

        assertThat(parsed).containsEntry("plaintext", "dGVzdA==");
    }

    @Test
    void roundtrip_vaultAuthResponse_parsesCorrectly() {
        String authResponse = """
                {
                    "auth": {
                        "client_token": "hvs.CAESIJlU",
                        "accessor": "0e9e354a-520f-df04-6867-ee81cae3d42d",
                        "policies": ["default", "transit-policy"],
                        "lease_duration": 3600,
                        "renewable": true
                    }
                }
                """;

        Map<String, Object> result = JsonUtil.parseObject(authResponse);
        assertThat(result).containsKey("auth");

        @SuppressWarnings("unchecked")
        Map<String, Object> auth = (Map<String, Object>) result.get("auth");
        assertThat(auth).containsEntry("client_token", "hvs.CAESIJlU");
        assertThat(auth).containsEntry("renewable", true);
        assertThat(auth).containsEntry("lease_duration", 3600);
    }
}
