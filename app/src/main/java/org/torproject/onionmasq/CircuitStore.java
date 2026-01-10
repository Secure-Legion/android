package org.torproject.onionmasq;

import androidx.annotation.NonNull;

import org.torproject.onionmasq.circuit.Circuit;
import org.torproject.onionmasq.circuit.CircuitCountryCodes;
import org.torproject.onionmasq.circuit.ProxyAddressPair;
import org.torproject.onionmasq.events.ClosedConnectionEvent;
import org.torproject.onionmasq.events.FailedConnectionEvent;
import org.torproject.onionmasq.events.NewConnectionEvent;
import org.torproject.onionmasq.events.OnionmasqEvent;
import org.torproject.onionmasq.events.RelayDetails;
import org.torproject.onionmasq.logging.LogObservable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.WeakHashMap;

/**
 * CircuitStore parses Onionmasq connectivity events and keeps track of open tor socket connections per
 * app (uid).
 *
 * Based on once opened socket connections, country codes involved in a tor circuit are stored per app.
 * Unlike tracked socket connections, these country codes are not removed once all socket connections on a circuit have been closed.
 * The reason for it is that we want to allow the UI to display established circuits
 * for an app, no matter some data is sent from or to the app just in the moment the user checks these
 * details. In the current rust-implementation an apps circuit should to be reused for every new established socket connection, unless
 * a refresh of a circuit for an app was triggered or the old circuit has become unusable. For now we keep the country
 * codes of the last created socket connection per app. In the future, when an app is allowed to create socket connections over multiple circuits,
 * a change of the onionmasq rust API will be required to receive events that are signaling properly
 * the creation and dismissal of circuits per app.
 */
class CircuitStore {

    /**
     *  key: Application UID
     *  value: HashSet of open socket connections related to an app
     */
    private final HashMap<Integer, HashSet<ProxyAddressPair>> appUIdMap = new HashMap<>();

    private final WeakHashMap<ProxyAddressPair, NewConnectionEvent> connectionMap = new WeakHashMap<>();

    private final HashMap<Integer, CircuitCountryCodes> countryCodeMap = new HashMap<>();



    public void handleEvent(OnionmasqEvent event) {
        if (event instanceof NewConnectionEvent) {
            handleNewConnectionEvent((NewConnectionEvent) event);
        } else if (event instanceof ClosedConnectionEvent) {
            handleClosedConnectionEvent((ClosedConnectionEvent) event);
        } else if (event instanceof FailedConnectionEvent) {
            handleFailedConnectionEvent((FailedConnectionEvent) event);
        }
        // else ignore
    }

    public void reset() {
        connectionMap.clear();
        appUIdMap.clear();
        countryCodeMap.clear();
    }

    protected @NonNull ArrayList<CircuitCountryCodes> getCircuitCountryCodesForAppUid(int appUID) throws NullPointerException {
        ArrayList<CircuitCountryCodes> resultList = new ArrayList<>();
        CircuitCountryCodes ccc = countryCodeMap.get(appUID);
        if (ccc != null) {
            resultList.add(ccc);
        }
       return resultList;
    }

    protected @NonNull ArrayList<Circuit> getCircuitsForAppUid(int appUID) {
        HashSet<ProxyAddressPair> keys = appUIdMap.get(appUID);
        if (keys == null) {
            return new ArrayList<>();
        }

        HashSet<Circuit> resultList = new HashSet<>();
        for (ProxyAddressPair key : keys) {
            NewConnectionEvent connectionEvent = connectionMap.get(key);
            if (connectionEvent == null) {
                // this should never happen. Let's verify that for a while
                throw new NullPointerException("Connection map returned null!");
            }
            Circuit circuit = new Circuit(connectionEvent.circuit, connectionEvent.torDst);
            resultList.add(circuit);
        }

        return new ArrayList<>(resultList);
    }


    private void handleNewConnectionEvent(NewConnectionEvent event) {
        ProxyAddressPair key = new ProxyAddressPair(event.proxySrc, event.proxyDst);
        HashSet<ProxyAddressPair> proxyAddressPairs = appUIdMap.getOrDefault(event.appId, new HashSet<>());
        proxyAddressPairs.add(key);
        appUIdMap.put(event.appId, proxyAddressPairs);
        connectionMap.put(key, event);
        addCircuitCountryCodes(event);
    }

    private void addCircuitCountryCodes(NewConnectionEvent event) {
        ArrayList<String> ccList = new ArrayList<>();
        for (RelayDetails relayDetails : event.circuit) {
            ccList.add(relayDetails.country_code);
        }
        countryCodeMap.put(event.appId, new CircuitCountryCodes(ccList));
    }

    public void removeCircuitCountryCodes(int appId) {
        countryCodeMap.remove(appId);
    }

    private void handleClosedConnectionEvent(ClosedConnectionEvent event) {
        ProxyAddressPair key = new ProxyAddressPair(event.proxySrc, event.proxyDst);
        NewConnectionEvent connectionEvent = connectionMap.get(key);
        if (connectionEvent == null) {
            // event might have been removed if the connection failed before
            return;
        }

        HashSet<ProxyAddressPair> proxyAddressPairs = appUIdMap.get(connectionEvent.appId);
        if (proxyAddressPairs != null) {
            proxyAddressPairs.remove(key);
            if (proxyAddressPairs.isEmpty()) {
                appUIdMap.remove(connectionEvent.appId);
                return;
            }
            appUIdMap.put(connectionEvent.appId, proxyAddressPairs);
        }
    }

    private void handleFailedConnectionEvent(FailedConnectionEvent event) {
        ProxyAddressPair key = new ProxyAddressPair(event.proxySrc, event.proxyDst);
        NewConnectionEvent connectionEvent = connectionMap.get(key);
        if (connectionEvent == null) {
            LogObservable.getInstance().addLog("WARNING: Unknown FailedConnectionEvent with proxySrc:proxyDst tuple " + event.proxySrc + ":" + event.proxyDst);
            return;
        }
        HashSet<ProxyAddressPair> proxyAddressPairs = appUIdMap.get(connectionEvent.appId);
        if (proxyAddressPairs != null) {
            proxyAddressPairs.remove(key);
            if (proxyAddressPairs.isEmpty()) {
                appUIdMap.remove(connectionEvent.appId);
                return;
            }
            appUIdMap.put(connectionEvent.appId, proxyAddressPairs);
        }
    }

}

