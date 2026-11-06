package app.kukuvpn.core.warp

import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64

/**
 * Pure-Kotlin RFC 7748 X25519 (Curve25519 scalar multiplication) for minting a
 * fresh WireGuard keypair on the device. Needed because java.security does not
 * expose X25519 below API 33 and we support API 24+.
 *
 * The implementation follows the Montgomery-ladder procedure in RFC 7748 §5
 * ("All calculations are performed in GF(p)") and has been verified against the
 * RFC 7748 §6.1 test vectors (Alice/Bob key pairs and the shared secret).
 */
object X25519 {

    /** Field prime p = 2^255 - 19. */
    private val P: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))

    /** (486662 - 2) / 4, the ladder constant for curve25519. */
    private val A24: BigInteger = BigInteger.valueOf(121665)

    /** Base point u = 9 encoded as 32 little-endian bytes. */
    private val BASE_POINT: ByteArray = ByteArray(32).also { it[0] = 9 }

    fun generatePrivateKey(random: SecureRandom = SecureRandom()): ByteArray =
        ByteArray(32).also(random::nextBytes)

    fun publicKeyFromPrivate(privateKey: ByteArray): ByteArray =
        scalarMult(privateKey, BASE_POINT)

    fun toBase64(key: ByteArray): String = Base64.getEncoder().encodeToString(key)

    /**
     * RFC 7748 §5 procedure. Scalars and u-coordinates are decoded little-endian
     * (the scalar is clamped inside, as the RFC specifies), the result is encoded
     * little-endian in exactly 32 bytes.
     */
    private fun scalarMult(rawScalar: ByteArray, rawU: ByteArray): ByteArray {
        // decodeScalar25519: clamp the scalar
        val k = rawScalar.copyOf()
        k[0] = (k[0].toInt() and 248).toByte()
        k[31] = ((k[31].toInt() and 127) or 64).toByte()
        val kInt = BigInteger(1, k.reversedArray()) // little-endian decode

        // decodeUCoordinate: mask the most significant bit of the final byte
        val u = rawU.copyOf()
        u[31] = (u[31].toInt() and 127).toByte()
        val x1 = BigInteger(1, u.reversedArray()).mod(P) // little-endian decode

        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = false

        for (t in 254 downTo 0) {
            val kT = kInt.testBit(t)
            val doSwap = swap xor kT
            if (doSwap) {
                val tmpX = x2; x2 = x3; x3 = tmpX
                val tmpZ = z2; z2 = z3; z3 = tmpZ
            }
            swap = kT

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)

            // x_3 = (DA + CB)^2
            x3 = da.add(cb).mod(P).pow(2).mod(P)
            // z_3 = x_1 * (DA - CB)^2  — note: only (DA - CB) is squared, x_1 is a factor
            z3 = x1.multiply(da.subtract(cb).mod(P).pow(2)).mod(P)
            // x_2 = AA * BB
            x2 = aa.multiply(bb).mod(P)
            // z_2 = E * (AA + a24 * E)
            z2 = e.multiply(aa.add(A24.multiply(e))).mod(P)
        }
        if (swap) {
            val tmpX = x2; x2 = x3; x3 = tmpX
            val tmpZ = z2; z2 = z3; z3 = tmpZ
        }

        val result = x2.multiply(z2.modPow(P.subtract(BigInteger.TWO), P)).mod(P)
        return encodeLittleEndian(result)
    }

    /** Encode a field element (< 2^255) as exactly 32 little-endian bytes. */
    private fun encodeLittleEndian(v: BigInteger): ByteArray {
        val be = v.toByteArray() // big-endian, possibly with a leading zero byte
        var first = 0
        while (first < be.size - 1 && be[first] == 0.toByte()) first++
        val sig = be.copyOfRange(first, be.size) // significant bytes, most significant first
        val out = ByteArray(32)
        for (i in sig.indices) out[i] = sig[sig.size - 1 - i]
        return out
    }
}
