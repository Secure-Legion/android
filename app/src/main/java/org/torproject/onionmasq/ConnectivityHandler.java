package org.torproject.onionmasq;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Process;

import androidx.annotation.NonNull;

import org.torproject.onionmasq.errors.ProxyStoppedException;
import org.torproject.onionmasq.events.ConnectivityEvent;
import org.torproject.onionmasq.events.VPNetworkLostEvent;
import org.torproject.onionmasq.logging.LogObservable;

public class ConnectivityHandler {

    ConnectivityManager connectivityManager;
    int appUID = Process.INVALID_UID;
    String vpnID = "";

    private final NetworkCallback networkCallback = new NetworkCallback() {
        @Override
        public void onAvailable(@NonNull Network network) {
            super.onAvailable(network);
            LogObservable.getInstance().addLog("Internet connectivity available.");

            // Beginning from Android O, onAvailable is always immediately followed by onCapabilitiesChanged
            // which we check separately.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                try {
                    OnionMasqJni.setInternetConnectivity(true);
                    OnionMasq.handleEvent(new ConnectivityEvent(true));
                } catch (ProxyStoppedException e) {
                    e.printStackTrace();
                }
            }
        }

        @Override
        public void onLost(@NonNull Network network) {
            super.onLost(network);
            LogObservable.getInstance().addLog("Internet connectivity lost.");
            try {
                if (OnionMasq.isRunning()) {
                    OnionMasqJni.setInternetConnectivity(false);
                }
            } catch (ProxyStoppedException e) {
                e.printStackTrace();
            }
            OnionMasq.handleEvent(new ConnectivityEvent(false));
        }

        @Override
        public void onCapabilitiesChanged(@NonNull Network network, @NonNull NetworkCapabilities networkCapabilities) {
            super.onCapabilitiesChanged(network, networkCapabilities);
            boolean hasInternetConnectivity = networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
            LogObservable.getInstance().addLog("Network capabilities changed. Internet connectivity:"  + hasInternetConnectivity);
            try {
                if (OnionMasq.isRunning()) {
                    OnionMasqJni.setInternetConnectivity(hasInternetConnectivity);
                }
            } catch (ProxyStoppedException e) {
                e.printStackTrace();
            }
            OnionMasq.handleEvent(new ConnectivityEvent(hasInternetConnectivity));
        }
    };

    private final NetworkCallback vpnNetworkCallback = new NetworkCallback() {
        @Override
        public void onLost(@NonNull Network network) {
            super.onLost(network);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                if (vpnID != null && vpnID.equals(network.toString())) {
                    OnionMasq.handleEvent(new VPNetworkLostEvent());
                    vpnID = null;
                }
            } else {
                // on Android Versions pre API 30 (Android 11), we cannot determine if the
                // lost VPN network belongs to our app, so we need to send the VPNetworkLostEvent
                // unconditionally and it's up to the receiver of the event to determine the state
                // of its VPN service
                OnionMasq.handleEvent(new VPNetworkLostEvent());
            }
        }


        @Override
        public void onCapabilitiesChanged(@NonNull Network network, @NonNull NetworkCapabilities networkCapabilities) {
            super.onCapabilitiesChanged(network, networkCapabilities);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                if (networkCapabilities.getOwnerUid() == appUID) {
                    vpnID = network.toString();
                }
            }
        }
    };


    // It is recommended to pass an application context since this handler is likely to be a long-living
    // component
    public ConnectivityHandler(Context context) {
        connectivityManager = (ConnectivityManager) context.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        appUID = android.os.Process.myUid();
    }

    public void register() {
        NetworkRequest networkRequest = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
                .addTransportType(NetworkCapabilities.TRANSPORT_BLUETOOTH)
                .build();
        connectivityManager.requestNetwork(networkRequest, networkCallback);
        NetworkRequest vpnNetworkRequest = new NetworkRequest.Builder()
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                .build();
        connectivityManager.requestNetwork(vpnNetworkRequest, vpnNetworkCallback);

        Network currentNetwork = connectivityManager.getActiveNetwork();
        if (currentNetwork != null) {
            NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(currentNetwork);
            boolean hasConnectivity = capabilities != null && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
            OnionMasq.handleEvent(new ConnectivityEvent(hasConnectivity));
        } else {
            OnionMasq.handleEvent(new ConnectivityEvent(false));
        }
    }

    public void unregister() {
        connectivityManager.unregisterNetworkCallback(networkCallback);
        connectivityManager.unregisterNetworkCallback(vpnNetworkCallback);
    }

}
