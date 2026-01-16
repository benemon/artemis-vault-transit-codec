package com.hashicorp.vault.client;

/**
 * Utility class for argument validation.
 */
final class Preconditions {

    private Preconditions() {
        // Utility class
    }

    /**
     * Validates that a string is neither null nor blank.
     *
     * @param value the value to check
     * @param name  the parameter name for the error message
     * @throws IllegalArgumentException if the value is null or blank
     */
    static void requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " cannot be null or blank");
        }
    }
}
