package org.torproject.onionmasq.events;

public class ConnectivityEvent extends OnionmasqEvent {

    public boolean hasInternetConnectivity;
    public ConnectivityEvent(boolean hasInternetConnectivity) {
        this.hasInternetConnectivity = hasInternetConnectivity;
    }
}
