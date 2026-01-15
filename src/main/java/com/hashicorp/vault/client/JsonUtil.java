package com.hashicorp.vault.client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON utilities for Vault API communication.
 *
 * <p>This class provides simple JSON serialization and parsing without external
 * dependencies. It handles the limited JSON structures used by the Vault API:
 * <ul>
 *   <li>Objects with string, number, boolean, null, object, and array values</li>
 *   <li>Arrays of strings (for error messages)</li>
 * </ul>
 *
 * <p>This is intentionally minimal - for more complex JSON needs, consider
 * adding a proper JSON library.
 */
public final class JsonUtil {

    private JsonUtil() {
        // Utility class
    }

    /**
     * Serializes a map to JSON string.
     *
     * <p>Supports String, Number, Boolean, null, Map, and List values.
     *
     * @param map the map to serialize
     * @return the JSON string
     */
    public static String toJson(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return "{}";
        }

        StringBuilder sb = new StringBuilder("{");
        boolean first = true;

        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;

            sb.append("\"").append(escapeString(entry.getKey())).append("\":");
            appendValue(sb, entry.getValue());
        }

        sb.append("}");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void appendValue(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String) {
            sb.append("\"").append(escapeString((String) value)).append("\"");
        } else if (value instanceof Number) {
            sb.append(value);
        } else if (value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map) {
            sb.append(toJson((Map<String, Object>) value));
        } else if (value instanceof List) {
            appendList(sb, (List<?>) value);
        } else {
            // Fallback: convert to string
            sb.append("\"").append(escapeString(value.toString())).append("\"");
        }
    }

    private static void appendList(StringBuilder sb, List<?> list) {
        sb.append("[");
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            appendValue(sb, item);
        }
        sb.append("]");
    }

    private static String escapeString(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * Parses a JSON string into a Map.
     *
     * @param json the JSON string
     * @return the parsed map, or null if parsing fails
     */
    public static Map<String, Object> parseObject(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }

        try {
            Parser parser = new Parser(json.trim());
            return parser.parseObject();
        } catch (Exception e) {
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

    /**
     * Simple recursive descent JSON parser.
     */
    private static class Parser {
        private final String json;
        private int pos;

        Parser(String json) {
            this.json = json;
            this.pos = 0;
        }

        Map<String, Object> parseObject() {
            skipWhitespace();
            expect('{');
            skipWhitespace();

            Map<String, Object> map = new HashMap<>();

            if (peek() != '}') {
                do {
                    skipWhitespace();
                    String key = parseString();
                    skipWhitespace();
                    expect(':');
                    skipWhitespace();
                    Object value = parseValue();
                    map.put(key, value);
                    skipWhitespace();
                } while (consume(','));
            }

            expect('}');
            return map;
        }

        List<Object> parseArray() {
            expect('[');
            skipWhitespace();

            List<Object> list = new ArrayList<>();

            if (peek() != ']') {
                do {
                    skipWhitespace();
                    list.add(parseValue());
                    skipWhitespace();
                } while (consume(','));
            }

            expect(']');
            return list;
        }

        Object parseValue() {
            skipWhitespace();
            char c = peek();

            if (c == '"') {
                return parseString();
            } else if (c == '{') {
                return parseObject();
            } else if (c == '[') {
                return parseArray();
            } else if (c == 't' || c == 'f') {
                return parseBoolean();
            } else if (c == 'n') {
                return parseNull();
            } else if (c == '-' || Character.isDigit(c)) {
                return parseNumber();
            } else {
                throw new IllegalStateException("Unexpected character: " + c + " at position " + pos);
            }
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();

            while (pos < json.length()) {
                char c = json.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                } else if (c == '\\') {
                    if (pos >= json.length()) {
                        throw new IllegalStateException("Unexpected end of string");
                    }
                    char escaped = json.charAt(pos++);
                    switch (escaped) {
                        case '"':
                        case '\\':
                        case '/':
                            sb.append(escaped);
                            break;
                        case 'b':
                            sb.append('\b');
                            break;
                        case 'f':
                            sb.append('\f');
                            break;
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'u':
                            if (pos + 4 > json.length()) {
                                throw new IllegalStateException("Invalid unicode escape");
                            }
                            String hex = json.substring(pos, pos + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                            break;
                        default:
                            sb.append(escaped);
                    }
                } else {
                    sb.append(c);
                }
            }

            throw new IllegalStateException("Unterminated string");
        }

        Number parseNumber() {
            int start = pos;

            if (peek() == '-') {
                pos++;
            }

            while (pos < json.length() && Character.isDigit(json.charAt(pos))) {
                pos++;
            }

            boolean isDouble = false;
            if (pos < json.length() && json.charAt(pos) == '.') {
                isDouble = true;
                pos++;
                while (pos < json.length() && Character.isDigit(json.charAt(pos))) {
                    pos++;
                }
            }

            if (pos < json.length() && (json.charAt(pos) == 'e' || json.charAt(pos) == 'E')) {
                isDouble = true;
                pos++;
                if (pos < json.length() && (json.charAt(pos) == '+' || json.charAt(pos) == '-')) {
                    pos++;
                }
                while (pos < json.length() && Character.isDigit(json.charAt(pos))) {
                    pos++;
                }
            }

            String numStr = json.substring(start, pos);
            if (isDouble) {
                return Double.parseDouble(numStr);
            } else {
                long value = Long.parseLong(numStr);
                if (value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE) {
                    return (int) value;
                }
                return value;
            }
        }

        Boolean parseBoolean() {
            if (json.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            } else if (json.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new IllegalStateException("Expected boolean at position " + pos);
        }

        Object parseNull() {
            if (json.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new IllegalStateException("Expected null at position " + pos);
        }

        void skipWhitespace() {
            while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) {
                pos++;
            }
        }

        char peek() {
            if (pos >= json.length()) {
                throw new IllegalStateException("Unexpected end of JSON");
            }
            return json.charAt(pos);
        }

        void expect(char c) {
            if (peek() != c) {
                throw new IllegalStateException("Expected '" + c + "' but found '" + peek() + "' at position " + pos);
            }
            pos++;
        }

        boolean consume(char c) {
            if (pos < json.length() && json.charAt(pos) == c) {
                pos++;
                return true;
            }
            return false;
        }
    }
}
