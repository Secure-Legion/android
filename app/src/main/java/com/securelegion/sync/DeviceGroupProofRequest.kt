package com.securelegion.sync

/** Encrypted C2 proof request: sorted exact public operation hashes only. */
internal object DeviceGroupProofRequest {
    private val MAGIC = "SLPQ01".toByteArray(Charsets.US_ASCII)

    fun encode(hashes: Collection<String>): ByteArray {
        val ordered = hashes.distinct().sorted()
        require(ordered.size in 1..16 && ordered.all {
            it.matches(Regex("[0-9a-f]{64}"))
        })
        val result = ByteArray(7 + ordered.size * 32)
        MAGIC.copyInto(result)
        result[6] = ordered.size.toByte()
        for ((index, hash) in ordered.withIndex())
            for (byte in 0 until 32)
                result[7 + index * 32 + byte] =
                    hash.substring(byte * 2, byte * 2 + 2).toInt(16).toByte()
        return result
    }

    fun decode(input: ByteArray): List<String> {
        require(input.size in 39..519 && input.copyOfRange(0, 6)
            .contentEquals(MAGIC))
        val count = input[6].toInt() and 255
        require(count in 1..16 && input.size == 7 + count * 32)
        val hashes = ArrayList<String>(count)
        for (index in 0 until count) {
            val hash = input.copyOfRange(7 + index * 32, 39 + index * 32)
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            require(hashes.isEmpty() || hashes.last() < hash)
            hashes.add(hash)
        }
        return hashes
    }
}
