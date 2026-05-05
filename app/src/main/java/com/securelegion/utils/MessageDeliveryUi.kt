package com.securelegion.utils

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Network
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.annotation.StringRes
import com.securelegion.R
import com.securelegion.database.entities.Message

/**
 * UI-only projection for outbound delivery labels.
 *
 * This deliberately does not change Message.status. Retry/backoff continues to
 * use the real protocol state, while the UI can optimistically show Sent.
 */
object MessageDeliveryUi {
    const val ACK_TIMEOUT_MS = 120_000L

    @StringRes
    fun statusTextRes(
        context: Context,
        message: Message,
        nowMs: Long = System.currentTimeMillis()
    ): Int = statusTextRes(
        context = context,
        status = message.status,
        isSentByMe = message.isSentByMe,
        messageDelivered = message.messageDelivered,
        timestampMs = message.timestamp,
        nowMs = nowMs
    )

    @StringRes
    fun statusTextRes(
        context: Context,
        status: Int,
        isSentByMe: Boolean,
        messageDelivered: Boolean,
        timestampMs: Long,
        nowMs: Long = System.currentTimeMillis()
    ): Int {
        if (!isSentByMe) return R.string.message_status_pending

        return when {
            messageDelivered -> R.string.message_status_delivered
            !hasInternet(context) -> R.string.message_status_pending
            hasAckTimeoutExpired(timestampMs, nowMs) -> R.string.message_status_pending
            else -> R.string.message_status_sent
        }
    }

    fun millisUntilAckTimeoutRefresh(
        status: Int,
        isSentByMe: Boolean,
        messageDelivered: Boolean,
        timestampMs: Long,
        nowMs: Long = System.currentTimeMillis()
    ): Long? {
        if (!isSentByMe) return null
        if (messageDelivered) {
            return null
        }
        if (timestampMs <= 0L) return null

        val elapsedMs = nowMs - timestampMs
        if (elapsedMs < 0L || elapsedMs >= ACK_TIMEOUT_MS) return null
        return ACK_TIMEOUT_MS - elapsedMs
    }

    fun millisUntilAckTimeoutRefresh(
        message: Message,
        nowMs: Long = System.currentTimeMillis()
    ): Long? = millisUntilAckTimeoutRefresh(
        status = message.status,
        isSentByMe = message.isSentByMe,
        messageDelivered = message.messageDelivered,
        timestampMs = message.timestamp,
        nowMs = nowMs
    )

    fun registerNetworkChangeCallback(
        context: Context,
        onChanged: () -> Unit
    ): ConnectivityManager.NetworkCallback? {
        val connectivityManager = context.applicationContext
            .getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        val mainHandler = Handler(Looper.getMainLooper())
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                mainHandler.post(onChanged)
            }

            override fun onLost(network: Network) {
                mainHandler.post(onChanged)
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities
            ) {
                mainHandler.post(onChanged)
            }
        }

        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                connectivityManager.registerDefaultNetworkCallback(callback)
            } else {
                val request = NetworkRequest.Builder().build()
                connectivityManager.registerNetworkCallback(request, callback)
            }
            callback
        } catch (_: Exception) {
            null
        }
    }

    fun unregisterNetworkChangeCallback(
        context: Context,
        callback: ConnectivityManager.NetworkCallback?
    ) {
        if (callback == null) return
        val connectivityManager = context.applicationContext
            .getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return
        try {
            connectivityManager.unregisterNetworkCallback(callback)
        } catch (_: Exception) {
            // Callback may already be unregistered by the platform lifecycle.
        }
    }

    private fun hasAckTimeoutExpired(timestampMs: Long, nowMs: Long): Boolean {
        return timestampMs > 0L && nowMs - timestampMs >= ACK_TIMEOUT_MS
    }

    @Suppress("DEPRECATION")
    private fun hasInternet(context: Context): Boolean {
        val connectivityManager = context.applicationContext
            .getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val activeNetwork = connectivityManager.activeNetwork ?: return false
            val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork) ?: return false
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        } else {
            connectivityManager.activeNetworkInfo?.isConnected == true
        }
    }
}
