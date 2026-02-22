package com.securelegion.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class VoiceClipAdapter(
    private val voiceItems: List<VoiceItem>
) : RecyclerView.Adapter<VoiceClipAdapter.ViewHolder>() {

    data class VoiceItem(
        val voiceFilePath: String?,
        val durationSeconds: Int,
        val timestamp: Long,
        val isSentByMe: Boolean
    )

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val duration: TextView = view.findViewById(R.id.voiceDuration)
        val timestamp: TextView = view.findViewById(R.id.voiceTimestamp)
        val sender: TextView = view.findViewById(R.id.voiceSender)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_voice_clip, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = voiceItems[position]

        // Format duration as m:ss
        val mins = item.durationSeconds / 60
        val secs = item.durationSeconds % 60
        holder.duration.text = "$mins:${String.format("%02d", secs)}"

        // Format timestamp
        val dateFormat = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
        holder.timestamp.text = dateFormat.format(Date(item.timestamp))

        holder.sender.text = if (item.isSentByMe) "Sent" else "Received"
    }

    override fun getItemCount(): Int = voiceItems.size
}
