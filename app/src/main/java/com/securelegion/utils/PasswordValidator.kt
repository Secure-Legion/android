package com.securelegion.utils

/**
 * Password Validator
 *
 * Enforces password complexity requirements:
 * - Minimum 9 characters
 * - Must contain uppercase, lowercase, number, and special character
 * - Cannot be common weak passwords or sequential patterns
 */
object PasswordValidator {

    private val WEAK_PASSWORDS = setOf(
        "12345678", "123456789", "1234567890",
        "password", "password1", "password123",
        "qwerty", "qwerty123", "qwertyuiop",
        "abc123", "abcdefgh", "abcd1234",
        "admin", "admin123", "administrator",
        "welcome", "welcome1", "welcome123",
        "letmein", "monkey", "dragon"
    )

    data class ValidationResult(
        val isValid: Boolean,
        val errorMessage: String? = null
    )

    /**
     * Validate password against security requirements
     */
    fun validate(password: String): ValidationResult {
        // Check minimum length
        if (password.length < 9) {
            return ValidationResult(false, "Password must be at least 9 characters")
        }

        // Check for common weak passwords
        if (WEAK_PASSWORDS.contains(password.lowercase())) {
            return ValidationResult(false, "Password is too common")
        }

        // Check for sequential numbers (e.g., 123456, 987654)
        if (hasSequentialNumbers(password)) {
            return ValidationResult(false, "Password cannot contain sequential numbers")
        }

        // Check for repeated characters (e.g., 111111, aaaaaa)
        if (hasRepeatedCharacters(password)) {
            return ValidationResult(false, "Password has too many repeated characters")
        }

        // Check for at least one uppercase letter
        if (!password.any { it.isUpperCase() }) {
            return ValidationResult(false, "Password must contain at least one uppercase letter")
        }

        // Check for at least one lowercase letter
        if (!password.any { it.isLowerCase() }) {
            return ValidationResult(false, "Password must contain at least one lowercase letter")
        }

        // Check for at least one number
        if (!password.any { it.isDigit() }) {
            return ValidationResult(false, "Password must contain at least one number")
        }

        // Check for at least one special character
        if (!password.any { !it.isLetterOrDigit() }) {
            return ValidationResult(false, "Password must contain at least one special character (!@#\$%^&*)")
        }

        return ValidationResult(true)
    }

    /**
     * Check if password contains sequential numbers (3+ in a row)
     * Examples: 123, 234, 987, 876
     */
    private fun hasSequentialNumbers(password: String): Boolean {
        for (i in 0 until password.length - 2) {
            val c1 = password[i]
            val c2 = password[i + 1]
            val c3 = password[i + 2]

            if (c1.isDigit() && c2.isDigit() && c3.isDigit()) {
                val n1 = c1.digitToInt()
                val n2 = c2.digitToInt()
                val n3 = c3.digitToInt()

                // Ascending sequence (e.g., 123, 345)
                if (n2 == n1 + 1 && n3 == n2 + 1) {
                    return true
                }

                // Descending sequence (e.g., 987, 765)
                if (n2 == n1 - 1 && n3 == n2 - 1) {
                    return true
                }
            }
        }
        return false
    }

    /**
     * Check if password has repeated characters (4+ of the same character)
     * Examples: 1111, aaaa, !!!!
     */
    private fun hasRepeatedCharacters(password: String): Boolean {
        var count = 1
        for (i in 1 until password.length) {
            if (password[i] == password[i - 1]) {
                count++
                if (count >= 4) {
                    return true
                }
            } else {
                count = 1
            }
        }
        return false
    }
}
