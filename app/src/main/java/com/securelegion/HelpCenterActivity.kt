package com.securelegion

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.core.text.HtmlCompat
import com.securelegion.utils.ThemedToast

class HelpCenterActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_help_center)

        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        setHtml(R.id.connectionIssuesBody, """
            Check the connection pill at the top of the Messages screen. It shows your current Tor connection status.<br/><br/>
            &#8226; <b>Green (Connected)</b><br/>Your connection is active and working normally.<br/><br/>
            &#8226; <b>Yellow (Connecting)</b><br/>The app is still establishing a Tor connection. Wait a moment for it to finish.<br/><br/>
            &#8226; <b>Red (Disconnected)</b><br/>The connection has failed or dropped. Tap the pill to open the VPN connect screen and reconnect.<br/><br/>
            If tapping the pill does not resolve the issue, go to Settings &gt; Tor VPN Settings and toggle the tunnel off, then back on to restart the connection.
        """.trimIndent())

        setHtml(R.id.bootstrapBody, """
            When connecting, you will see a bootstrap percentage that indicates how far along the Tor connection process is.<br/><br/>
            &#8226; <b>0 - 24%</b><br/>Starting up. The app is initializing the Tor client and finding directory information.<br/><br/>
            &#8226; <b>25 - 49%</b><br/>Loading network consensus. The app is downloading information about available Tor relays.<br/><br/>
            &#8226; <b>50 - 74%</b><br/>Building circuits. The app is establishing encrypted paths through the Tor network.<br/><br/>
            &#8226; <b>75 - 99%</b><br/>Almost ready. Circuits are being tested and finalized.<br/><br/>
            &#8226; <b>100%</b><br/>Fully connected. You will see "Established Circuit" which means a secure path through the Tor network is active and ready.<br/><br/>
            "Established Circuit" means your device has successfully built an encrypted route through multiple Tor relays and you can send and receive messages.
        """.trimIndent())

        setHtml(R.id.torNodesBody, """
            Your connection is routed through multiple relays (nodes) for privacy. Each node only knows the node before and after it, so no single relay can see your full path.<br/><br/>
            &#8226; <b>Entry Node (Guard)</b><br/>The first relay your device connects to. It knows your real IP address but cannot see your destination or message content.<br/><br/>
            &#8226; <b>Middle Node (Relay)</b><br/>An intermediate relay that passes encrypted traffic between the entry and exit nodes. It cannot see the source or destination.<br/><br/>
            &#8226; <b>Exit Node</b><br/>The final relay in the circuit. For hidden services (.onion addresses), there is no traditional exit node since traffic stays within the Tor network.<br/><br/>
            "New Circuit" forces the app to build a fresh path through different Tor relays. Use this if your connection feels slow or if you want to change your route for additional privacy. It does not disconnect you, it simply switches to a new set of relays.
        """.trimIndent())

        findViewById<View>(R.id.startHelpChatButton).setOnClickListener {
            ThemedToast.show(this, "Help Chat coming soon")
        }
    }

    private fun setHtml(id: Int, html: String) {
        findViewById<TextView>(id).text =
            HtmlCompat.fromHtml(html, HtmlCompat.FROM_HTML_MODE_COMPACT)
    }
}
