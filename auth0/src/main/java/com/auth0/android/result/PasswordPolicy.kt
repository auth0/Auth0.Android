package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Describes the password policy that a new password must satisfy, as returned by the My Account API
 * when starting a password enrollment. Use it to build a UI that guides the user toward a compliant
 * password. All fields are nullable to tolerate policies that only configure a subset of rules.
 */
public data class PasswordPolicy(
    /**
     * Rules governing the structural complexity of the password (length, character types, etc.).
     */
    @SerializedName("complexity")
    public val complexity: PasswordComplexity?,
    /**
     * Rules that prevent the password from containing personal information taken from the user profile.
     */
    @SerializedName("profile_data")
    public val profileData: PasswordProfileData?,
    /**
     * Rules that prevent reuse of previously used passwords.
     */
    @SerializedName("history")
    public val history: PasswordHistory?,
    /**
     * Rules that prevent the use of common dictionary words as passwords.
     */
    @SerializedName("dictionary")
    public val dictionary: PasswordDictionary?
)

/**
 * Structural complexity requirements for a password.
 */
public data class PasswordComplexity(
    /**
     * The minimum number of characters the password must contain.
     */
    @SerializedName("min_length")
    public val minLength: Int?,
    /**
     * The character classes the password may be required to include.
     * Possible values: `uppercase`, `lowercase`, `number`, `special`.
     */
    @SerializedName("character_types")
    public val characterTypes: List<String>?,
    /**
     * How the [characterTypes] requirement is enforced.
     * Possible values: `all` (every listed type is required), `three_of_four`.
     */
    @SerializedName("character_type_rule")
    public val characterTypeRule: String?,
    /**
     * Whether identical consecutive characters are permitted.
     * Possible values: `allow`, `block`.
     */
    @SerializedName("identical_characters")
    public val identicalCharacters: String?,
    /**
     * Whether sequential characters (e.g. `abc`, `123`) are permitted.
     * Possible values: `allow`, `block`.
     */
    @SerializedName("sequential_characters")
    public val sequentialCharacters: String?,
    /**
     * How a password that exceeds the maximum allowed length is handled.
     * Possible values: `truncate`, `error`.
     */
    @SerializedName("max_length_exceeded")
    public val maxLengthExceeded: String?
)

/**
 * Rules that block the use of personal information from the user profile within a password.
 */
public data class PasswordProfileData(
    /**
     * Whether blocking of personal information is enabled.
     */
    @SerializedName("active")
    public val active: Boolean?,
    /**
     * The user profile fields whose values must not appear in the password
     * (e.g. `name`, `email`, `user_metadata.first`).
     */
    @SerializedName("blocked_fields")
    public val blockedFields: List<String>?
)

/**
 * Rules that prevent reuse of previously used passwords.
 */
public data class PasswordHistory(
    /**
     * Whether password history enforcement is enabled.
     */
    @SerializedName("active")
    public val active: Boolean?,
    /**
     * The number of previous passwords that cannot be reused.
     */
    @SerializedName("size")
    public val size: Int?
)

/**
 * Rules that prevent the use of common dictionary words as passwords.
 */
public data class PasswordDictionary(
    /**
     * Whether dictionary checking is enabled.
     */
    @SerializedName("active")
    public val active: Boolean?,
    /**
     * The default dictionary used for the check.
     * Possible values: `en_10k`, `en_100k`.
     */
    @SerializedName("default")
    public val default: String?
)
