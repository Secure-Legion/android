package com.securelegion.sync

/** Private SLGB01 body. The caller must clear it after the SQLCipher transaction. */
internal class DeviceGroupBundle private constructor(
    private val bytes: ByteArray,
    val mode: Mode,
    val groupKey: ByteArray,
    val historyReceipt: ByteArray,
    val packedOperations: ByteArray,
    val ratifications: List<ByteArray>,
    val rosters: List<RosterObservation>
) {
    enum class Mode(val code: Int) {
        LIVE(1), INVITATION(2), REINVITATION(3), PROOFS_ONLY(4);
        companion object { fun from(code: Int) = entries.firstOrNull { it.code == code } }
    }
    data class RosterObservation(val account: ByteArray, val encoded: ByteArray)

    private var cleared = false
    fun encoded(): ByteArray {
        check(!cleared)
        return bytes.copyOf()
    }

    fun clear() {
        bytes.fill(0)
        groupKey.fill(0)
        historyReceipt.fill(0)
        packedOperations.fill(0)
        ratifications.forEach { it.fill(0) }
        rosters.forEach { it.account.fill(0); it.encoded.fill(0) }
        cleared = true
    }

    companion object {
        const val MAX_PACKED_BYTES = 24 * 1024 * 1024
        private const val RECEIPT_BYTES = 408
        private val MAGIC = "SLGB01".toByteArray(Charsets.US_ASCII)
        private val PROOF_MAGIC = "SLGR01".toByteArray(Charsets.US_ASCII)

        fun parse(input: ByteArray): DeviceGroupBundle {
            require(input.size in 20..DeviceGroupFrame.MAX_BUNDLE_BYTES)
            val bytes = input.copyOf()
            var at = 0
            val owned = ArrayList<ByteArray>()
            fun take(n: Int): ByteArray {
                require(n >= 0 && n <= bytes.size - at) { "Truncated SLGB bundle" }
                return bytes.copyOfRange(at, at + n).also { at += n; owned.add(it) }
            }
            fun u8() = take(1)[0].toInt() and 0xff
            fun u16(): Int {
                val b = take(2)
                return ((b[0].toInt() and 0xff) shl 8) or (b[1].toInt() and 0xff)
            }
            fun u32(): Long = take(4).fold(0L) { value, byte ->
                (value shl 8) or (byte.toLong() and 0xff)
            }
            try {
                require(take(6).contentEquals(MAGIC))
                val mode = Mode.from(u8()) ?: throw IllegalArgumentException("Unknown SLGB mode")
                val key = take(u8())
                val receipt = take(u16())
                require(if (mode == Mode.LIVE || mode == Mode.PROOFS_ONLY)
                    key.isEmpty() && receipt.isEmpty() else
                    key.size == 32 && receipt.size == RECEIPT_BYTES)
                val opLength = u32()
                require(opLength <= MAX_PACKED_BYTES &&
                    (mode == Mode.PROOFS_ONLY) == (opLength == 0L))
                val packed = take(opLength.toInt())
                val proofCount = u32()
                require(proofCount <= (bytes.size - at) / 134 &&
                    (mode != Mode.PROOFS_ONLY || proofCount in 1..16))
                val proofs = ArrayList<ByteArray>(proofCount.toInt())
                var lastProof: ByteArray? = null
                repeat(proofCount.toInt()) {
                    val proof = take(134)
                    val hash = proof.copyOfRange(6, 38)
                    require(proof.copyOfRange(0, 6).contentEquals(PROOF_MAGIC) &&
                        (lastProof == null || compare(lastProof!!, hash) < 0))
                    lastProof = hash
                    proofs.add(proof)
                }
                val rosterCount = u16()
                require(rosterCount <= 128 &&
                    (mode != Mode.PROOFS_ONLY || rosterCount == 0))
                val rosters = ArrayList<RosterObservation>(rosterCount)
                var lastAccount: ByteArray? = null
                repeat(rosterCount) {
                    val account = take(32)
                    val length = u16()
                    require(length in 1..DeviceGroupFrame.MAX_ROSTER_BYTES &&
                        (lastAccount == null || compare(lastAccount!!, account) < 0))
                    rosters.add(RosterObservation(account, take(length)))
                    lastAccount = account
                }
                require(at == bytes.size) { "Trailing SLGB bytes" }
                return DeviceGroupBundle(bytes, mode, key, receipt, packed, proofs, rosters)
            } catch (error: Exception) {
                bytes.fill(0)
                owned.forEach { it.fill(0) }
                throw error
            }
        }

        fun create(mode: Mode, groupKey: ByteArray = ByteArray(0),
                   historyReceipt: ByteArray = ByteArray(0),
                   packedOperations: ByteArray = ByteArray(0),
                   ratifications: List<ByteArray> = emptyList(),
                   rosters: List<RosterObservation> = emptyList()): DeviceGroupBundle {
            require(if (mode == Mode.LIVE || mode == Mode.PROOFS_ONLY)
                groupKey.isEmpty() && historyReceipt.isEmpty() else
                groupKey.size == 32 && historyReceipt.size == RECEIPT_BYTES)
            require(packedOperations.size <= MAX_PACKED_BYTES &&
                (mode == Mode.PROOFS_ONLY) == packedOperations.isEmpty() &&
                (mode != Mode.PROOFS_ONLY ||
                    ratifications.size in 1..16 && rosters.isEmpty()) &&
                ratifications.all { it.size == 134 } && rosters.size <= 128)
            val proofs = ratifications.sortedWith { a, b ->
                compare(a.copyOfRange(6, 38), b.copyOfRange(6, 38))
            }
            val orderedRosters = rosters.sortedWith { a, b -> compare(a.account, b.account) }
            require(proofs.zipWithNext().all { (a, b) ->
                compare(a.copyOfRange(6, 38), b.copyOfRange(6, 38)) < 0
            } && orderedRosters.zipWithNext().all { (a, b) ->
                compare(a.account, b.account) < 0
            })
            val size = 6 + 1 + 1 + groupKey.size + 2 + historyReceipt.size + 4 +
                packedOperations.size + 4 + 134 * proofs.size + 2 +
                orderedRosters.sumOf { 34 + it.encoded.size }
            require(size <= DeviceGroupFrame.MAX_BUNDLE_BYTES)
            val encoded = ByteArray(size)
            var at = 0
            fun add(bytes: ByteArray) {
                bytes.copyInto(encoded, at)
                at += bytes.size
            }
            fun u16(value: Int) = add(byteArrayOf((value ushr 8).toByte(), value.toByte()))
            fun u32(value: Int) = add(byteArrayOf((value ushr 24).toByte(),
                (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte()))
            add(MAGIC)
            encoded[at++] = mode.code.toByte()
            encoded[at++] = groupKey.size.toByte()
            add(groupKey)
            u16(historyReceipt.size)
            add(historyReceipt)
            u32(packedOperations.size)
            add(packedOperations)
            u32(proofs.size)
            proofs.forEach(::add)
            u16(orderedRosters.size)
            for (roster in orderedRosters) {
                require(roster.account.size == 32 &&
                    roster.encoded.size in 1..DeviceGroupFrame.MAX_ROSTER_BYTES)
                add(roster.account)
                u16(roster.encoded.size)
                add(roster.encoded)
            }
            check(at == encoded.size)
            return try { parse(encoded) } finally { encoded.fill(0) }
        }

        private fun compare(a: ByteArray, b: ByteArray): Int {
            for (i in 0 until minOf(a.size, b.size)) {
                val compared = (a[i].toInt() and 0xff).compareTo(b[i].toInt() and 0xff)
                if (compared != 0) return compared
            }
            return a.size.compareTo(b.size)
        }
    }
}
