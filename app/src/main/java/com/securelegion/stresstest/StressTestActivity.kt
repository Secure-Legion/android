package com.securelegion.stresstest

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.*
import android.widget.FrameLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Stress Test Activity - Minimal UI for diagnosing SOCKS timeout and MESSAGE_TX race
 * Uses real MessageService pipeline (no simulation)
 */
class StressTestActivity : AppCompatActivity() {

    private val TAG = "StressTestActivity"

    // UI Components
    private lateinit var scenarioSpinner: Spinner
    private lateinit var messageCountInput: EditText
    private lateinit var contactSpinner: Spinner
    private lateinit var startButton: FrameLayout
    private lateinit var stopButton: FrameLayout
    private lateinit var sentCountText: TextView
    private lateinit var deliveredCountText: TextView
    private lateinit var failedCountText: TextView
    private lateinit var eventLogRecyclerView: RecyclerView
    private lateinit var dumpCountersButton: FrameLayout
    private lateinit var resetStateButton: FrameLayout

    // Stress Test Components
    private val store = StressTestStore()
    private lateinit var engine: StressTestEngine
    private lateinit var eventAdapter: EventLogAdapter

    // Contact list
    private val contacts = mutableListOf<ContactItem>()
    private var selectedContactId: Long = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_stress_test)

        // Setup back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Initialize UI components
        scenarioSpinner = findViewById(R.id.scenarioSpinner)
        messageCountInput = findViewById(R.id.messageCountInput)
        contactSpinner = findViewById(R.id.contactSpinner)
        startButton = findViewById(R.id.startButton)
        stopButton = findViewById(R.id.stopButton)
        sentCountText = findViewById(R.id.sentCountText)
        deliveredCountText = findViewById(R.id.deliveredCountText)
        failedCountText = findViewById(R.id.failedCountText)
        eventLogRecyclerView = findViewById(R.id.eventLogRecyclerView)
        dumpCountersButton = findViewById(R.id.dumpCountersButton)
        resetStateButton = findViewById(R.id.resetStateButton)

        // Initialize stress test engine
        engine = StressTestEngine(this, store)

        // Setup UI
        setupScenarioSpinner()
        setupContactSpinner()
        setupEventLog()
        setupButtons()

        // Start UI update loop
        startUIUpdateLoop()
    }

    private fun setupScenarioSpinner() {
        val scenarios = Scenario.values().map { it.name }
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, scenarios)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        scenarioSpinner.adapter = adapter
    }

    private fun setupContactSpinner() {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@StressTestActivity)
                val database = SecureLegionDatabase.getInstance(
                    this@StressTestActivity,
                    keyManager.getDatabasePassphrase()
                )

                contacts.clear()
                val allContacts = database.contactDao().getAllContacts()
                contacts.addAll(allContacts.map { ContactItem(it.id, it.displayName) })

                withContext(Dispatchers.Main) {
                    val names = contacts.map { it.name }
                    val adapter = ArrayAdapter(
                        this@StressTestActivity,
                        android.R.layout.simple_spinner_item,
                        names
                    )
                    adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
                    contactSpinner.adapter = adapter

                    contactSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                        override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                            selectedContactId = contacts[position].id
                        }

                        override fun onNothingSelected(parent: AdapterView<*>?) {}
                    }

                    // Select first contact by default
                    if (contacts.isNotEmpty()) {
                        selectedContactId = contacts[0].id
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load contacts", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@StressTestActivity, "Failed to load contacts")
                }
            }
        }
    }

    private fun setupEventLog() {
        eventAdapter = EventLogAdapter()
        eventLogRecyclerView.layoutManager = LinearLayoutManager(this)
        eventLogRecyclerView.adapter = eventAdapter
    }

    private fun setupButtons() {
        startButton.setOnClickListener {
            startStressTest()
        }

        stopButton.setOnClickListener {
            stopStressTest()
        }

        dumpCountersButton.setOnClickListener {
            dumpDebugCounters()
        }

        resetStateButton.setOnClickListener {
            resetState()
        }
    }

    private fun startStressTest() {
        val scenarioName = scenarioSpinner.selectedItem.toString()
        val scenario = Scenario.valueOf(scenarioName)

        val messageCount = messageCountInput.text.toString().toIntOrNull() ?: 10

        if (selectedContactId == 0L) {
            ThemedToast.show(this, "Please select a contact")
            return
        }

        val config = StressTestConfig(
            scenario = scenario,
            messageCount = messageCount,
            contactId = selectedContactId
        )

        Log.i(TAG, "Starting stress test: $scenario with $messageCount messages")

        engine.start(config)

        // Update UI state
        startButton.isEnabled = false
        stopButton.isEnabled = true
        scenarioSpinner.isEnabled = false
        messageCountInput.isEnabled = false
        contactSpinner.isEnabled = false

        ThemedToast.show(this, "Stress test started")
    }

    private fun stopStressTest() {
        Log.i(TAG, "Stopping stress test")
        engine.stop()

        // Update UI state
        startButton.isEnabled = true
        stopButton.isEnabled = false
        scenarioSpinner.isEnabled = true
        messageCountInput.isEnabled = true
        contactSpinner.isEnabled = true

        ThemedToast.show(this, "Stress test stopped")
    }

    private fun dumpDebugCounters() {
        lifecycleScope.launch {
            try {
                val countersJson = withContext(Dispatchers.IO) {
                    RustBridge.getDebugCountersJson()
                }

                Log.i(TAG, "")
                Log.i(TAG, "DEBUG COUNTERS DUMP")
                Log.i(TAG, "$countersJson")
                Log.i(TAG, "")

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@StressTestActivity, "Counters dumped to logcat")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to dump counters", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@StressTestActivity, "Failed to dump counters")
                }
            }
        }
    }

    private fun resetState() {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    RustBridge.resetDebugCounters()
                }

                store.clear()
                eventAdapter.clear()

                withContext(Dispatchers.Main) {
                    sentCountText.text = "Sent: 0"
                    deliveredCountText.text = "OK: 0"
                    failedCountText.text = "FAIL: 0"
                    ThemedToast.show(this@StressTestActivity, "State reset")
                }

                Log.i(TAG, "State reset complete")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to reset state", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@StressTestActivity, "Failed to reset state")
                }
            }
        }
    }

    private fun startUIUpdateLoop() {
        lifecycleScope.launch {
            while (true) {
                updateUI()
                delay(500) // Update every 500ms
            }
        }
    }

    private fun updateUI() {
        val summary = store.getSummary()

        sentCountText.text = "Sent: ${summary.totalSent}"
        deliveredCountText.text = "OK: ${summary.totalDelivered}"
        failedCountText.text = "FAIL: ${summary.totalFailed}"

        // Update event log (show last 100 events)
        val events = store.getEvents().takeLast(100)
        eventAdapter.updateEvents(events)
    }

    override fun onDestroy() {
        super.onDestroy()
        engine.stop()
    }

    data class ContactItem(val id: Long, val name: String)
}
