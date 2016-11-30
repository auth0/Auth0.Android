package com.auth0.android.provider;

final class FlagChecker {

    /**
     * Helper method to check that a given value contains a specific flag.
     *
     * @param value       the value to check
     * @param flagToCheck the required flag
     * @return true if the flag is present in the value, false otherwise.
     */
    static boolean hasFlag(int value, int flagToCheck) {
        return ((value & flagToCheck) == flagToCheck);
    }
}
