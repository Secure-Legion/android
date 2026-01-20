package com.securelegion.network

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first

/**
 * Global gate that blocks/allows all Tor network operations.
 *
 * When a network change occurs, gate is CLOSED until Tor probe succeeds.
 * All Tor operations must call awaitOpen() before proceeding.
 *
 * This prevents "Tor says running but nothing moves" freeze.
 */
class TransportGate {
    companion object {
        private const val TAG = "TransportGate"
    }

    private val isOpen = MutableStateFlow(false)

    /**
     * Block all Tor network operations until gate opens.
     * Suspend until probe confirms Tor is working.
     */
    suspend fun awaitOpen() {
        Log.d(TAG, "Awaiting gate open...")
        isOpen.filter { it }.first()
        Log.d(TAG, "Gate opened, proceeding with network operation")
    }

    /**
     * Close gate, block all operations.
     * Called during network switch or restart sequence.
     */
    fun close() {
        Log.w(TAG, "Closing transport gate - blocking all Tor operations")
        isOpen.value = false
    }

    /**
     * Open gate, allow operations.
     * Called only after Tor probe succeeds.
     */
    fun open() {
        Log.i(TAG, "Opening transport gate - Tor verified working")
        isOpen.value = true
    }

    fun isOpenNow(): Boolean = isOpen.value
}
