package com.auth0.sample

import java.security.SecureRandom

class RandomString(length: Int) {
    private val random = SecureRandom()
    private val buf: CharArray
    fun nextString(): String {
        for (idx in buf.indices) buf[idx] = symbols[random.nextInt(symbols.length)]
        return String(buf)
    }

    companion object {
        /* Assign a string that contains the set of characters you allow. */
        private const val symbols = "0123456789abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    }

    init {
        require(length >= 1) { "length < 1: $length" }
        buf = CharArray(length)
    }
}
