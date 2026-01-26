package com.securelegion.stresstest

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import java.text.SimpleDateFormat
import java.util.*

/**
 * Simple adapter for stress test event log
 * Shows events in chronological order with color-coded status
 */
class EventLogAdapter : RecyclerView.Adapter<EventLogAdapter.EventViewHolder>() {

    private val events = mutableListOf<StressEvent>()
    private val dateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    fun updateEvents(newEvents: List<StressEvent>) {
        events.clear()
        events.addAll(newEvents)
        notifyDataSetChanged()
    }

    fun clear() {
        events.clear()
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): EventViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(android.R.layout.simple_list_item_1, parent, false)
        return EventViewHolder(view)
    }

    override fun onBindViewHolder(holder: EventViewHolder, position: Int) {
        val event = events[position]
        holder.bind(event)
    }

    override fun getItemCount(): Int = events.size

    inner class EventViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val textView: TextView = itemView.findViewById(android.R.id.text1)

        fun bind(event: StressEvent) {
            val timestamp = dateFormat.format(Date(event.timestampMs))

            val (text, color) = when (event) {
                is StressEvent.RunStarted ->
                    "$timestamp RUN_START ${event.runId.id}" to 0xFFFFFFFF.toInt()

                is StressEvent.MessageAttempt ->
                    "$timestamp ATTEMPT cid=${event.correlationId.takeLast(8)}" to 0xFFA0AEC0.toInt()

                is StressEvent.Phase -> {
                    val statusColor = if (event.ok) 0xFF10B981.toInt() else 0xFFEF4444.toInt()
                    val detail = event.detail?.let { " ($it)" } ?: ""
                    "$timestamp ${event.phase} cid=${event.correlationId.takeLast(8)}$detail" to statusColor
                }

                is StressEvent.Progress ->
                    "$timestamp PROGRESS sent=${event.sent} ok=${event.delivered} fail=${event.failed}" to 0xFFA0AEC0.toInt()

                is StressEvent.RunFinished ->
                    "$timestamp RUN_END ${event.durationMs}ms" to 0xFFFFFFFF.toInt()
            }

            textView.text = text
            textView.setTextColor(color)
            textView.textSize = 10f
            textView.setBackgroundColor(0xFF0A0E14.toInt())
        }
    }
}
