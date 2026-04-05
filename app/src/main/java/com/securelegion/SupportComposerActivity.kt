package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.Spinner
import androidx.appcompat.widget.SwitchCompat
import androidx.lifecycle.lifecycleScope
import com.securelegion.utils.SupportChatRepository
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.launch

/**
 * Screen for composing a support ticket. Mirrors the iOS support composer.
 * On Next: creates a local-only support thread, inserts the ticket + auto-reply,
 * and returns the user to the chat list where the thread will appear.
 */
class SupportComposerActivity : BaseActivity() {

    private val reasons = arrayOf(
        "General",
        "Account",
        "Friend Request",
        "Messaging",
        "Media",
        "Notifications",
        "Other"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_support_composer)

        val reasonSpinner = findViewById<Spinner>(R.id.reasonSpinner)
        reasonSpinner.adapter = ArrayAdapter(
            this,
            R.layout.item_support_reason_selected,
            reasons
        ).apply {
            setDropDownViewResource(R.layout.item_support_reason_dropdown)
        }

        findViewById<View>(R.id.closeButton).setOnClickListener { finish() }

        findViewById<View>(R.id.nextButton).setOnClickListener { submit(reasonSpinner) }
    }

    private fun submit(reasonSpinner: Spinner) {
        val reason = reasons[reasonSpinner.selectedItemPosition]
        val details = findViewById<EditText>(R.id.detailsInput).text.toString().trim()
        val includeDebug = findViewById<SwitchCompat>(R.id.includeDebugToggle).isChecked

        if (details.isEmpty()) {
            ThemedToast.show(this, "Please describe your issue")
            return
        }

        lifecycleScope.launch {
            SupportChatRepository.submitTicket(
                this@SupportComposerActivity,
                reason,
                details,
                includeDebug
            )
            ThemedToast.show(this@SupportComposerActivity, "Support ticket created")
            val intent = Intent(this@SupportComposerActivity, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            startActivity(intent)
            finish()
        }
    }
}
