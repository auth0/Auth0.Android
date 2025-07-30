package com.auth0.android.dpop

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

/**
 * Fake Private key used for testing DPoP
 */
public class FakeEcPrivateKey : ECPrivateKey {

    private companion object {
        private val S =
            BigInteger("7a45666f486007b850d9a65499271a39d803562334533e7f4c4b6a213e27d144", 16)

        private val EC_PARAMETER_SPEC: ECParameterSpec = try {
            val params = AlgorithmParameters.getInstance("EC")
            params.init(ECGenParameterSpec("secp256r1"))
            params.getParameterSpec(ECParameterSpec::class.java)
        } catch (e: Exception) {
            throw IllegalStateException("Cannot initialize ECParameterSpec for secp256r1", e)
        }

        private val PKCS8_ENCODED = BigInteger(
            "307702010104207a45666f486007b850d9a65499271a39d803562334533e7f4c4b6a213e27d144a00a06082a8648ce3d030107a144034200049405d454a853686891083c27e873e4497d5a5c68b556b23d9a65349e5480579e4d1f2e245c43d81577918a90184b25e11438992f0724817163f9eb2050b1",
            16
        ).toByteArray()
    }


    /**
     * Returns the private value s.
     */
    override fun getS(): BigInteger = S

    /**
     * The name of the algorithm for this key.
     */
    override fun getAlgorithm(): String = "EC"

    /**
     * The name of the encoding format.
     */
    override fun getFormat(): String = "PKCS#8"

    /**
     * Returns the key in its primary encoding format (PKCS#8).
     */
    override fun getEncoded(): ByteArray = PKCS8_ENCODED

    /**
     * Returns the elliptic curve domain parameters.
     */
    override fun getParams(): ECParameterSpec = EC_PARAMETER_SPEC

    override fun toString(): String = "Fake EC Private Key (secp256r1) [Kotlin]"
}

/**
 * Fake Public key used for testing DPoP
 */
public class FakeECPublicKey : ECPublicKey {
    override fun getAlgorithm(): String = "EC"
    override fun getFormat(): String = "X.509"
    override fun getEncoded(): ByteArray = ByteArray(64) { 0x02 } // Dummy encoded key

    override fun getParams(): ECParameterSpec {
        val curve = ECParameterSpec(
            null, // Replace with a valid EllipticCurve if needed
            ECPoint(BigInteger.ONE, BigInteger.TWO), // Dummy generator point
            BigInteger.TEN, // Dummy order
            1 // Dummy cofactor
        )
        return curve
    }

    override fun getW(): ECPoint = ECPoint(BigInteger.ONE, BigInteger.TWO) // Dummy point
}