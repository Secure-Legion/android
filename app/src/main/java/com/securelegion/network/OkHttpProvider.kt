package com.securelegion.network

import android.util.Log
import okhttp3.OkHttpClient
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * Centralized OkHttpClient provider for Tor-proxied HTTP requests
 *
 * All HTTP clients route through Tor SOCKS5 proxy at 127.0.0.1:9050
 * Call reset() when network changes to clear stale connections
 */
object OkHttpProvider {
    private const val TAG = "OkHttpProvider"

    @Volatile
    private var _solanaClient: OkHttpClient? = null

    @Volatile
    private var _crustClient: OkHttpClient? = null

    @Volatile
    private var _zcashClient: OkHttpClient? = null

    @Volatile
    private var _genericClient: OkHttpClient? = null

    @Volatile
    private var lastResetAt = 0L

    /**
     * Get OkHttpClient for Solana RPC calls
     * Longer timeouts for blockchain API delays
     */
    fun getSolanaClient(): OkHttpClient {
        return _solanaClient ?: synchronized(this) {
            _solanaClient ?: buildClient(
                connectTimeout = 60,
                readTimeout = 60,
                writeTimeout = 60
            ).also { _solanaClient = it }
        }
    }

    /**
     * Get OkHttpClient for IPFS/Crust operations
     * Standard timeouts for file uploads
     */
    fun getCrustClient(): OkHttpClient {
        return _crustClient ?: synchronized(this) {
            _crustClient ?: buildClient(
                connectTimeout = 30,
                readTimeout = 30,
                writeTimeout = 30
            ).also { _crustClient = it }
        }
    }

    /**
     * Get OkHttpClient for Zcash price fetching
     * Standard timeouts
     */
    fun getZcashClient(): OkHttpClient {
        return _zcashClient ?: synchronized(this) {
            _zcashClient ?: buildClient(
                connectTimeout = 30,
                readTimeout = 30,
                writeTimeout = 30
            ).also { _zcashClient = it }
        }
    }

    /**
     * Get generic OkHttpClient for miscellaneous Tor requests
     * Standard timeouts
     */
    fun getGenericClient(): OkHttpClient {
        return _genericClient ?: synchronized(this) {
            _genericClient ?: buildClient(
                connectTimeout = 30,
                readTimeout = 30,
                writeTimeout = 30
            ).also { _genericClient = it }
        }
    }

    /**
     * Reset all OkHttpClient instances (call after Tor restart or network change)
     * Evicts stale connections and cancels in-flight requests
     *
     * RATE-LIMITED: Only allows one reset per 30 seconds to prevent abuse
     *
     * @param reason Audit trail - why this reset was triggered (required)
     */
    fun reset(reason: String) {
        val now = System.currentTimeMillis()

        // Rate-limit hard resets to prevent thrashing
        if (now - lastResetAt < 30_000) {
            Log.w(TAG, "Skipping OkHttp reset (rate-limited, last reset ${(now - lastResetAt) / 1000}s ago). Reason=\"$reason\"")
            return
        }

        lastResetAt = now
        Log.e(TAG, "HARD OkHttp reset triggered. Reason=\"$reason\"")

        synchronized(this) {
            // Evict all connections from old clients
            _solanaClient?.run {
                connectionPool.evictAll()
                dispatcher.cancelAll()
            }
            _crustClient?.run {
                connectionPool.evictAll()
                dispatcher.cancelAll()
            }
            _zcashClient?.run {
                connectionPool.evictAll()
                dispatcher.cancelAll()
            }
            _genericClient?.run {
                connectionPool.evictAll()
                dispatcher.cancelAll()
            }

            // Force rebuild on next access
            _solanaClient = null
            _crustClient = null
            _zcashClient = null
            _genericClient = null

            Log.d(TAG, "All OkHttpClient instances reset")
        }
    }

    /**
     * Handle Tor stream failure WITHOUT resetting clients
     *
     * USE THIS for transient/retryable errors:
     * - SOCKS status 1 (general failure - usually means no circuits yet)
     * - SOCKS status 6 (TTL expired - circuit churn, normal)
     * - SOCKS status 4 (host unreachable - onion offline or descriptor delay)
     * - Connection timeout (peer offline or network slow)
     *
     * These are NORMAL Tor behavior and do NOT require tearing down all clients.
     * Just log + let the request retry naturally.
     */
    fun onTorStreamFailure() {
        // NO reset
        // NO cancel
        // Just log + metrics
        Log.w(TAG, "Tor stream failure (retryable), NOT resetting clients (this is normal)")
    }

    /**
     * Build OkHttpClient with Tor SOCKS5 proxy
     */
    private fun buildClient(
        connectTimeout: Long,
        readTimeout: Long,
        writeTimeout: Long
    ): OkHttpClient {
        return OkHttpClient.Builder()
            .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 9050)))
            .connectTimeout(connectTimeout, TimeUnit.SECONDS)
            .readTimeout(readTimeout, TimeUnit.SECONDS)
            .writeTimeout(writeTimeout, TimeUnit.SECONDS)
            .build()
    }
}
