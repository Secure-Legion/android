package com.securelegion.sync

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import org.json.JSONObject
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/** Pinned TLS 1.3 client bound to the active Wi-Fi network. */
internal class NearbyHistoryTlsConnection private constructor(
    private val context: Context,
    private val network: Network,
    private val socket: SSLSocket
) : Closeable {
    fun read(): JSONObject {
        checkWifi()
        return readRecord(socket.inputStream)
    }

    fun write(value: JSONObject) {
        checkWifi()
        writeRecord(socket.outputStream, value)
    }

    private fun checkWifi() {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val capabilities = manager.getNetworkCapabilities(network)
        require(capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) {
            "Nearby transfer requires active Wi-Fi"
        }
    }

    override fun close() { socket.close() }

    companion object {
        private const val MAX_RECORD = 768 * 1024
        private const val ALPN = "secure-history/1"
        private const val SNI = "secure-nearby.local"

        fun open(context: Context, offer: NearbyHistoryOfferWire.Offer): NearbyHistoryTlsConnection {
            require(NearbyHistoryOfferWire.privateIPv4(offer.host) &&
                offer.expiresAtMs > System.currentTimeMillis())
            val manager = context.getSystemService(ConnectivityManager::class.java)
            val network = manager.allNetworks.firstOrNull {
                manager.getNetworkCapabilities(it)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            } ?: throw IllegalStateException("Wi-Fi unavailable")
            val raw = network.socketFactory.createSocket()
            try {
                raw.soTimeout = 45_000
                raw.connect(InetSocketAddress(offer.host, offer.port), 15_000)
                val expected = offer.fingerprint
                val trust = object : X509TrustManager {
                    override fun getAcceptedIssuers() = emptyArray<X509Certificate>()
                    override fun checkClientTrusted(chain: Array<X509Certificate>,
                                                    authType: String) {
                        throw CertificateException("Client certificate not expected")
                    }
                    override fun checkServerTrusted(chain: Array<X509Certificate>,
                                                    authType: String) {
                        if (chain.isEmpty() || chain[0].encoded.sha256() != expected)
                            throw CertificateException("Nearby TLS leaf changed")
                    }
                }
                val sslContext = SSLContext.getInstance("TLSv1.3")
                sslContext.init(null, arrayOf(trust), null)
                val tls = sslContext.socketFactory.createSocket(raw, SNI, offer.port,
                    true) as SSLSocket
                try {
                    tls.enabledProtocols = arrayOf("TLSv1.3")
                    tls.sslParameters = tls.sslParameters.apply {
                        applicationProtocols = arrayOf(ALPN)
                        serverNames = listOf(SNIHostName(SNI))
                    }
                    tls.soTimeout = 45_000
                    tls.startHandshake()
                    require(tls.session.protocol == "TLSv1.3" &&
                        tls.applicationProtocol == ALPN)
                    require(manager.getNetworkCapabilities(network)
                            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true)
                    return NearbyHistoryTlsConnection(context.applicationContext,
                        network, tls)
                } catch (e: Exception) { tls.close(); throw e }
            } catch (e: Exception) { raw.close(); throw e }
        }

        fun readRecord(input: InputStream): JSONObject {
            val stream = DataInputStream(input)
            val count = stream.readInt()
            require(count in 2..MAX_RECORD)
            val bytes = ByteArray(count)
            stream.readFully(bytes)
            val text = Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
            return JSONObject(text)
        }

        fun writeRecord(output: OutputStream, value: JSONObject) {
            val bytes = value.toString().toByteArray(Charsets.UTF_8)
            require(bytes.size in 2..MAX_RECORD)
            val stream = DataOutputStream(output)
            stream.writeInt(bytes.size)
            stream.write(bytes)
            stream.flush()
        }

        private fun ByteArray.sha256(): String = MessageDigest.getInstance("SHA-256")
            .digest(this).joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
