package com.securelegion.sync

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.Closeable
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.X509ExtendedKeyManager
import javax.security.auth.x500.X500Principal

/** One-use TLS 1.3 listener pinned by a signed Nearby offer. */
internal class NearbyHistoryTlsServer private constructor(
    private val context: Context,
    private val network: Network,
    private val alias: String,
    private val keystore: KeyStore,
    private val listener: SSLServerSocket,
    val host: String,
    val port: Int,
    val fingerprint: String
) : Closeable {
    fun accept(): SSLSocket {
        checkWifi()
        val socket = listener.accept() as SSLSocket
        try {
            socket.soTimeout = 45_000
            socket.enabledProtocols = arrayOf("TLSv1.3")
            socket.sslParameters = socket.sslParameters.apply {
                applicationProtocols = arrayOf("secure-history/1")
            }
            socket.startHandshake()
            require(socket.session.protocol == "TLSv1.3" &&
                socket.applicationProtocol == "secure-history/1")
            checkWifi()
            return socket
        } catch (e: Exception) { socket.close(); throw e }
    }

    fun checkWifi() {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        require(manager.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) {
            "Nearby transfer requires Wi-Fi"
        }
    }

    override fun close() {
        runCatching { listener.close() }
        runCatching { keystore.deleteEntry(alias) }
    }

    companion object {
        fun open(context: Context): NearbyHistoryTlsServer {
            val app = context.applicationContext
            val manager = app.getSystemService(ConnectivityManager::class.java)
            val network = manager.allNetworks.firstOrNull {
                manager.getNetworkCapabilities(it)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true &&
                    manager.getLinkProperties(it)?.linkAddresses?.any { address ->
                        val host = address.address
                        host is Inet4Address &&
                            NearbyHistoryOfferWire.privateIPv4(host.hostAddress ?: "")
                    } == true
            } ?: error("Private Wi-Fi network unavailable")
            val host = manager.getLinkProperties(network)!!.linkAddresses
                .mapNotNull { it.address as? Inet4Address }
                .first { NearbyHistoryOfferWire.privateIPv4(it.hostAddress ?: "") }
            val alias = "secure-nearby-${java.util.UUID.randomUUID()}"
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            try {
                val now = System.currentTimeMillis()
                val serial = ByteArray(16).also { SecureRandom().nextBytes(it) }
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore").apply {
                    initialize(KeyGenParameterSpec.Builder(alias,
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                        .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                        .setCertificateSubject(X500Principal("CN=secure-nearby.local"))
                        .setCertificateSerialNumber(BigInteger(1, serial))
                        .setCertificateNotBefore(Date(now - 60_000))
                        .setCertificateNotAfter(Date(now + 3_600_000))
                        .setUserAuthenticationRequired(false).build())
                    generateKeyPair()
                }
                val certificate = store.getCertificate(alias) as X509Certificate
                val fingerprint = MessageDigest.getInstance("SHA-256")
                    .digest(certificate.encoded).joinToString("") {
                        "%02x".format(it.toInt() and 255) }
                val managerKey = object : X509ExtendedKeyManager() {
                    override fun getClientAliases(keyType: String?, issuers: Array<java.security.Principal>?) =
                        emptyArray<String>()
                    override fun chooseClientAlias(keyType: Array<String>?,
                                                   issuers: Array<java.security.Principal>?,
                                                   socket: java.net.Socket?) = null
                    override fun getServerAliases(keyType: String?,
                                                  issuers: Array<java.security.Principal>?) =
                        arrayOf(alias)
                    override fun chooseServerAlias(keyType: String?,
                                                   issuers: Array<java.security.Principal>?,
                                                   socket: java.net.Socket?) = alias
                    override fun chooseEngineServerAlias(keyType: String?,
                        issuers: Array<java.security.Principal>?,
                        engine: javax.net.ssl.SSLEngine?) = alias
                    override fun getCertificateChain(requested: String?) =
                        if (requested == alias) arrayOf(certificate) else null
                    override fun getPrivateKey(requested: String?): PrivateKey? =
                        if (requested == alias) store.getKey(alias, null) as? PrivateKey else null
                }
                val ssl = SSLContext.getInstance("TLSv1.3")
                ssl.init(arrayOf(managerKey), null, null)
                val listener = ssl.serverSocketFactory.createServerSocket() as SSLServerSocket
                try {
                    listener.enabledProtocols = arrayOf("TLSv1.3")
                    listener.soTimeout = 600_000
                    listener.bind(InetSocketAddress(host, 0), 1)
                    return NearbyHistoryTlsServer(app, network, alias, store,
                        listener, host.hostAddress ?: error("No Wi-Fi address"),
                        listener.localPort, fingerprint)
                } catch (e: Exception) { listener.close(); throw e }
            } catch (e: Exception) { store.deleteEntry(alias); throw e }
        }
    }
}
