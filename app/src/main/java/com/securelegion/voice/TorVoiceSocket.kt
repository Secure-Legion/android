package com.securelegion.voice

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.nio.ByteBuffer

/**
 * TorVoiceSocket wraps a TCP socket connection through Tor SOCKS5 proxy
 * Used for real-time bidirectional voice streaming to .onion addresses
 *
 * Each socket represents one Tor circuit for MCP-TV multi-circuit voice
 *
 * Connection flow:
 * 1. Create socket with SOCKS5 proxy (127.0.0.1:9050)
 * 2. Connect to recipient's .onion:port
 * 3. Send/receive VoiceFrame byte arrays
 * 4. Handle connection errors and reconnection
 */
class TorVoiceSocket(
    private val circuitIndex: Int = 0
) {
    companion object {
        private const val TAG = "TorVoiceSocket"

        // Tor SOCKS5 proxy address
        private const val TOR_SOCKS_HOST = "127.0.0.1"
        private const val TOR_SOCKS_PORT = 9050

        // Connection timeouts
        private const val CONNECT_TIMEOUT_MS = 60000 // 60 seconds for Tor circuit building
        private const val READ_TIMEOUT_MS = 10000     // 10 seconds for read operations
    }

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null

    @Volatile
    private var isConnected = false

    /**
     * Connect to recipient's hidden service through Tor SOCKS5 proxy
     * @param onionAddress Recipient's .onion address (without port)
     * @param port Hidden service port (e.g., 9150 for messaging onion)
     */
    suspend fun connect(onionAddress: String, port: Int) = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "[$circuitIndex] Connecting to $onionAddress:$port via Tor...")

            // Create SOCKS5 proxy
            val torProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(TOR_SOCKS_HOST, TOR_SOCKS_PORT))

            // Create socket with Tor proxy
            socket = Socket(torProxy)

            // Set timeouts
            socket?.soTimeout = READ_TIMEOUT_MS

            // Connect to .onion:port through Tor
            // This will create a new Tor circuit to the hidden service
            socket?.connect(InetSocketAddress(onionAddress, port), CONNECT_TIMEOUT_MS)

            // Get input/output streams
            inputStream = socket?.getInputStream()
            outputStream = socket?.getOutputStream()

            isConnected = true

            Log.i(TAG, "[$circuitIndex] Connected to $onionAddress:$port (circuit established)")

        } catch (e: IOException) {
            Log.e(TAG, "[$circuitIndex] Connection failed: ${e.message}", e)
            close()
            throw e
        }
    }

    /**
     * Send VoiceFrame over this circuit
     * @param frame VoiceFrame to send
     * @return True if sent successfully
     */
    suspend fun sendFrame(frame: VoiceFrame): Boolean = withContext(Dispatchers.IO) {
        val outputStream = this@TorVoiceSocket.outputStream
            ?: throw IllegalStateException("Socket not connected")

        try {
            val frameBytes = frame.toBytes()

            // Send frame length first (4 bytes, big-endian)
            val lengthBytes = ByteBuffer.allocate(4).putInt(frameBytes.size).array()
            outputStream.write(lengthBytes)

            // Send frame data
            outputStream.write(frameBytes)
            outputStream.flush()

            return@withContext true

        } catch (e: IOException) {
            Log.e(TAG, "[$circuitIndex] Send failed: ${e.message}", e)
            isConnected = false
            return@withContext false
        }
    }

    /**
     * Receive VoiceFrame from this circuit
     * Blocks until a frame is received
     * @return VoiceFrame, or null if connection closed
     */
    suspend fun receiveFrame(): VoiceFrame? = withContext(Dispatchers.IO) {
        val inputStream = this@TorVoiceSocket.inputStream
            ?: throw IllegalStateException("Socket not connected")

        try {
            // Read frame length (4 bytes, big-endian)
            val lengthBytes = ByteArray(4)
            var bytesRead = 0
            while (bytesRead < 4) {
                val n = inputStream.read(lengthBytes, bytesRead, 4 - bytesRead)
                if (n == -1) {
                    // Connection closed
                    Log.d(TAG, "[$circuitIndex] Connection closed by peer")
                    isConnected = false
                    return@withContext null
                }
                bytesRead += n
            }

            val frameLength = ByteBuffer.wrap(lengthBytes).int

            // Validate frame length
            if (frameLength <= 0 || frameLength > 10000) {
                Log.e(TAG, "[$circuitIndex] Invalid frame length: $frameLength")
                return@withContext null
            }

            // Read frame data
            val frameBytes = ByteArray(frameLength)
            bytesRead = 0
            while (bytesRead < frameLength) {
                val n = inputStream.read(frameBytes, bytesRead, frameLength - bytesRead)
                if (n == -1) {
                    Log.e(TAG, "[$circuitIndex] Connection closed while reading frame")
                    isConnected = false
                    return@withContext null
                }
                bytesRead += n
            }

            // Deserialize VoiceFrame
            return@withContext VoiceFrame.fromBytes(frameBytes)

        } catch (e: IOException) {
            Log.e(TAG, "[$circuitIndex] Receive failed: ${e.message}", e)
            isConnected = false
            return@withContext null
        }
    }

    /**
     * Check if socket is connected
     */
    fun isConnected(): Boolean = isConnected && socket?.isConnected == true && !socket!!.isClosed

    /**
     * Close the socket and streams
     */
    fun close() {
        isConnected = false

        try {
            outputStream?.close()
        } catch (e: IOException) {
            // Ignore
        }

        try {
            inputStream?.close()
        } catch (e: IOException) {
            // Ignore
        }

        try {
            socket?.close()
        } catch (e: IOException) {
            // Ignore
        }

        outputStream = null
        inputStream = null
        socket = null

        Log.d(TAG, "[$circuitIndex] Socket closed")
    }

    /**
     * Get circuit latency estimate (time for frame round-trip)
     * Used for adaptive circuit selection in MCP-TV
     * @return Latency in milliseconds, or -1 if unknown
     */
    fun getLatencyMs(): Long {
        // TODO: Implement ping/pong measurement
        // For now, return -1 (unknown)
        return -1
    }
}
