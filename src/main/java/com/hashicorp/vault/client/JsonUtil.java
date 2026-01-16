package com.hashicorp.vault.client;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * JSON utilities for Vault API communication using Gson.
 *
 * <p>This class provides JSON serialization and parsing for the Vault API.
 * It wraps Gson to provide a simple, consistent API for the limited JSON
 * structures used by Vault.
 */
public final class JsonUtil {

    private static final Gson GSON = new GsonBuilder()
            .serializeNulls()
            .create();

    private JsonUtil() {
        // Utility class
    }

    /**
     * Serializes a map to JSON string.
     *
     * @param map the map to serialize
     * @return the JSON string
     */
    public static String toJson(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return "{}";
        }
        return GSON.toJson(map);
    }

    /**
     * Parses a JSON string into a Map.
     *
     * @param json the JSON string
     * @return the parsed map, or null if parsing fails
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return GSON.fromJson(json, Map.class);
        } catch (JsonSyntaxException e) {
            return null;
        }
    }

    /**
     * Parses the "errors" field from a Vault error response.
     *
     * @param json the JSON response body
     * @return list of error messages, or null if not present
     */
    @SuppressWarnings("unchecked")
    public static List<String> parseErrors(String json) {
        Map<String, Object> root = parseObject(json);
        if (root == null) {
            return null;
        }

        Object errors = root.get("errors");
        if (errors instanceof List) {
            List<String> result = new ArrayList<>();
            for (Object item : (List<?>) errors) {
                if (item != null) {
                    result.add(item.toString());
                }
            }
            return result;
        }

        return null;
    }
}
