package org.torproject.onionmasq.events;

import android.util.Log;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import java.util.Objects;

/**
 * The base class for an asynchronous notification from the VPN tunnel.
 *
 * The events that can be received are all subclasses of this one; you should match against the
 * ones you support with `instanceof`. If an event can't be understood, you can use the
 * `rawJson` field inside this class if you wish.
 *
 * @see BootstrapEvent
 * @see ClosedConnectionEvent
 * @see FailedConnectionEvent
 * @see NewConnectionEvent
 */
public class OnionmasqEvent {
    /**
     * The raw JSON received from the VPN tunnel side.
     */
    public String rawJson;

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    public static OnionmasqEvent fromJson(String json) {
        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();

        JsonObject obj = gson.fromJson(json, JsonObject.class);
        String type = obj.get("type").getAsString();
        Class output_class = null;

        switch (type) {
            case "Bootstrap":
                output_class = BootstrapEvent.class;
                break;
            case "NewConnection":
                output_class = NewConnectionEvent.class;
                break;
            case "FailedConnection":
                output_class = FailedConnectionEvent.class;
                break;
            case "ClosedConnection":
                output_class = ClosedConnectionEvent.class;
                break;
            case "NewDirectory":
                output_class = NewDirectoryEvent.class;
                break;
            default:
                Log.e("OnionmasqEvent", "unknown event type: " + type);
                break;
        }

        if (output_class != null) {
            OnionmasqEvent result = (OnionmasqEvent) gson.fromJson(obj, output_class);
            result.rawJson = json;
            return result;
        }
        else {
            OnionmasqEvent ret = new OnionmasqEvent();
            ret.rawJson = json;
            return ret;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OnionmasqEvent)) return false;

        OnionmasqEvent that = (OnionmasqEvent) o;

        return Objects.equals(rawJson, that.rawJson);
    }

    @Override
    public int hashCode() {
        return rawJson != null ? rawJson.hashCode() : 0;
    }
}
