package org.torproject.onionmasq.logging;

import androidx.annotation.NonNull;

import org.torproject.onionmasq.utils.Utils;

import java.util.Locale;
import java.util.Objects;

public class LogItem {
    public final String content;
    public final long timestamp;

    public LogItem(long timestamp, String content) {
        this.timestamp = timestamp;
        this.content = content.trim();
    }

    @NonNull
    @Override
    public String toString() {
        return Utils.getFormattedDate(timestamp, Locale.getDefault()) + " " + content;
    }

    public String toString(boolean showTimestamp) {
        return showTimestamp ? toString() : content;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LogItem logItem = (LogItem) o;
        return timestamp == logItem.timestamp && Objects.equals(content, logItem.content);
    }

    @Override
    public int hashCode() {
        return Objects.hash(content, timestamp);
    }
}
