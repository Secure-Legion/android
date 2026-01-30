package org.torproject.onionmasq;

import static org.torproject.onionmasq.BridgeLineParser.AMP_CACHE;
import static org.torproject.onionmasq.BridgeLineParser.FRONTS;
import static org.torproject.onionmasq.BridgeLineParser.ICE;
import static org.torproject.onionmasq.BridgeLineParser.OBFS4;
import static org.torproject.onionmasq.BridgeLineParser.SNOWFLAKE;
import static org.torproject.onionmasq.BridgeLineParser.SQS_CREDS_STR;
import static org.torproject.onionmasq.BridgeLineParser.SQS_QUEUE_URL;
import static org.torproject.onionmasq.BridgeLineParser.URL;
import static org.torproject.onionmasq.BridgeLineParser.WEBTUNNEL;

import android.annotation.TargetApi;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.ConnectivityManager;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.WorkerThread;
import androidx.lifecycle.MutableLiveData;

import org.torproject.onionmasq.circuit.Circuit;
import org.torproject.onionmasq.circuit.CircuitCountryCodes;
import org.torproject.onionmasq.errors.CountryCodeException;
import org.torproject.onionmasq.errors.OnionmasqException;
import org.torproject.onionmasq.errors.ProxyStoppedException;
import org.torproject.onionmasq.events.OnionmasqEvent;
import org.torproject.onionmasq.logging.LogObservable;

import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;

import IPtProxy.Controller;
import IPtProxy.IPtProxy;
import IPtProxy.OnTransportEvents;

public class OnionMasq {

    private static final String TAG = OnionMasq.class.getSimpleName();
    private static OnionMasq instance;
    private final ConnectivityManager connectivityManager;
    private final Context appContext;
    private ISocketProtect serviceBinder;
    private final OnionmasqEventObservable eventObservable;
    private final CircuitStore circuitStore;
    private final static Object BRIDGE_CONFIG_LOCK = new Object();
    private final Controller iptController;

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName className,
                                       IBinder service) {
            if (service instanceof ISocketProtect) {
                serviceBinder = (ISocketProtect) service;
            } else {
                throw new IllegalArgumentException("Bound service needs to implement ISocketProtect interface");
            }

        }

        @Override
        public void onServiceDisconnected(ComponentName arg0) {
            serviceBinder = null;
        }
    };

    private static OnionMasq getInstance() throws IllegalStateException {
        if (instance == null) {
            throw new IllegalStateException("OnionmasqHelper is not initialized");
        }
        return instance;
    }

    public static void init(Context context) throws OnionmasqException {
        if (instance == null) {
            instance = new OnionMasq(context);
        }
    }

    private OnionMasq(Context context) throws OnionmasqException {
        this.appContext = context.getApplicationContext();
        this.connectivityManager = (ConnectivityManager) appContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        this.eventObservable = new OnionmasqEventObservable();
        this.circuitStore = new CircuitStore();
        this.iptController = initializeController(this.appContext);
        OnionMasqJni.init();
    }

    @TargetApi(Build.VERSION_CODES.Q)
    static int getConnectionOwnerUid(int protocol, byte[] rawSourceAddress, int sourcePort, byte[] rawDestinationAddress, int destinationPort) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                InetSocketAddress sourceSocketAddress = new InetSocketAddress(InetAddress.getByAddress(rawSourceAddress), sourcePort);
                InetSocketAddress destinationSocketAddress = new InetSocketAddress(InetAddress.getByAddress(rawDestinationAddress), destinationPort);
                return getInstance().connectivityManager.getConnectionOwnerUid(protocol, sourceSocketAddress, destinationSocketAddress);
            } catch (UnknownHostException | IllegalStateException e) {
                e.printStackTrace();
            }
        }

        return -1; // Process.INVALID_UID
    }

    public static void bindVPNService(Class vpnServiceClass) {
        Intent intent = new Intent(getInstance().appContext, vpnServiceClass);
        getInstance().appContext.bindService(intent, getInstance().connection, Context.BIND_AUTO_CREATE);
    }

    public static void unbindVPNService() {
        try {
            getInstance().appContext.unbindService(getInstance().connection);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
    }

    @WorkerThread
    public static synchronized void start(int fileDescriptor) throws OnionmasqException {
        start(fileDescriptor, null);
    }

    @WorkerThread
    public static synchronized void start(int fileDescriptor, String bridgeLines) throws OnionmasqException {
        try {
            BridgeLineParser.IPtConfig config = BridgeLineParser.getIPtConfigFrom(bridgeLines);
            startIPtProxy(config);
            OnionMasqJni.runProxy(
                    fileDescriptor,
                    // TODO: revert to cache dir, after arti has fixed handling of corrupted tor cache directory
                    getInstance().appContext.getFilesDir().getAbsolutePath(),
                    getInstance().appContext.getFilesDir().getAbsolutePath(),
                    config == null ? null : config.getBridgeType(),
                    config == null ? 0 : config.getPtClientPort(),
                    config == null ? null : config.getBridgeLines()
            );
        } catch (Exception e) {
            throw new OnionmasqException(e.getMessage());
        }
    }

    private static void startIPtProxy(BridgeLineParser.IPtConfig iPtConfig) throws Exception {
        synchronized (BRIDGE_CONFIG_LOCK) {
            if (iPtConfig == null || iPtConfig.getBridgeConfigs().isEmpty()) {
                Log.e(TAG, "No valid bridge configuration provided.");
                return;
            }

            try {

                switch (iPtConfig.getBridgeType()) {
                    case OBFS4 -> startObfs4Proxy();
                    case SNOWFLAKE -> startSnowflakeProxy(iPtConfig);
                    case WEBTUNNEL -> startWebtunnelProxy();
                    default -> Log.e(TAG, "Unknown bridge type: " + iPtConfig.getBridgeType());
                }

                iPtConfig.setPtClientPort((new URL("https://"+getInstance().iptController.localAddress(iPtConfig.getBridgeType()))).getPort());

            } catch (Exception e) {
                Log.e(TAG, "Failed to start IPtProxy: " + e.getMessage(), e);
                throw e;
            }
        }
    }

    private Controller initializeController(Context context)  {
        File ptDir = new File(context.getFilesDir().getAbsolutePath(), "pt_state");
        return IPtProxy.newController(ptDir.getAbsolutePath(), true, false, "DEBUG", new OnTransportEvents() {
            @Override
            public void stopped(String name, Exception error) {
                if (error != null) {
                    Log.e(TAG, "IPtProxy transport stopped: " + name + " error: " + error.getMessage());
                } else {
                    Log.i(TAG, "IPtProxy transport stopped: " + name);
                }
            }

            @Override
            public void error(String name, Exception error) {
                Log.e(TAG, "IPtProxy transport error: " + name + " - " + (error != null ? error.getMessage() : "unknown"));
            }

            @Override
            public void connected(String name) {
                Log.i(TAG, "IPtProxy transport connected: " + name);
            }
        });
    }

    private static void startObfs4Proxy() throws Exception {
        getInstance().iptController.start(IPtProxy.Obfs4, "");
    }

    private static void startWebtunnelProxy() throws Exception {
        getInstance().iptController.start(IPtProxy.Webtunnel, "");
    }

    /**
     * Starts the Snowflake proxy with the given configuration.
     * See <a href="https://github.com/tladesignz/IPtProxy/blob/4.1.2/IPtProxy.go/controller.go#L115-L136">Controller documentation</a>
     *
     * @param iPtConfig The IPtConfig containing the Snowflake configuration.
     * @throws Exception If an error occurs while starting the proxy.
     */
    private static void startSnowflakeProxy(BridgeLineParser.IPtConfig iPtConfig) throws Exception {
        Controller controller = getInstance().iptController;
        final int MAX_PEERS = 5;

        String iceServers = iPtConfig.getOption(ICE);
        String brokerUrl = iPtConfig.getOption(URL);
        String frontDomains = iPtConfig.getOption(FRONTS);
        String ampCacheUrl = iPtConfig.getOption(AMP_CACHE);
        String sqsUrl = iPtConfig.getOption(SQS_QUEUE_URL);
        String sqsCredentials = iPtConfig.getOption(SQS_CREDS_STR);

        if (iceServers != null) controller.setSnowflakeIceServers(iceServers);
        if (brokerUrl != null) controller.setSnowflakeBrokerUrl(brokerUrl);
        if (frontDomains != null) controller.setSnowflakeFrontDomains(frontDomains);
        if (ampCacheUrl != null) controller.setSnowflakeAmpCacheUrl(ampCacheUrl);
        if (sqsUrl != null) controller.setSnowflakeSqsUrl(sqsUrl);
        if (sqsCredentials != null) controller.setSnowflakeSqsCreds(sqsCredentials);

        controller.setSnowflakeMaxPeers(MAX_PEERS);
        controller.start(IPtProxy.Snowflake, "");
    }

    private static void stopIPtProxy() {
        synchronized (BRIDGE_CONFIG_LOCK) {
            getInstance().iptController.stop(IPtProxy.Snowflake);
            getInstance().iptController.stop(IPtProxy.Obfs4);
            getInstance().iptController.stop(IPtProxy.Webtunnel);
        }
    }

    public static boolean isRunning() {
        return OnionMasqJni.isRunning();
    }

    @WorkerThread
    public static void stop() {
        OnionMasqJni.closeProxy();
        OnionMasqJni.resetCounters();
        getInstance().circuitStore.reset();
        stopIPtProxy();
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void refreshCircuits() throws ProxyStoppedException {
        OnionMasqJni.refreshCircuits();
        getInstance().circuitStore.reset();
    }

    public static void refreshCircuitsForApp(long appId) throws ProxyStoppedException {
        OnionMasqJni.refreshCircuitsForApp(appId);
        getInstance().circuitStore.removeCircuitCountryCodes((int) appId);
    }

    static boolean protect(int socket) {
        if (getInstance().serviceBinder == null) {
            LogObservable.getInstance().addLog("Cannot protect Socket " + socket + ". VpnService is not registered.");
            return false;
        }

        return getInstance().serviceBinder.protect(socket);
    }

    public static MutableLiveData<OnionmasqEvent> getEventObservable() {
        return getInstance().eventObservable.getEvent();
    }

    static void handleEvent(OnionmasqEvent event) {
        getInstance().circuitStore.handleEvent(event);
        getInstance().eventObservable.update(event);
    }

    public static long getBytesReceived() {
        return OnionMasqJni.getBytesReceived();
    }

    public static long getBytesReceivedForApp(long appId) {
        return OnionMasqJni.getBytesReceivedForApp(appId);
    }

    public static long getBytesSent() {
        return OnionMasqJni.getBytesSent();
    }

    public static long getBytesSentForApp(long appId) {
        return OnionMasqJni.getBytesSentForApp(appId);
    }

    public static void resetCounters() {
        OnionMasqJni.resetCounters();
    }

    public static void setCountryCode(String cc) throws CountryCodeException {
        OnionMasqJni.setCountryCode(cc);
    }

    public static void setTurnServerConfig(String host, long port, String auth) {
        OnionMasqJni.setTurnServerConfig(host, port, auth);
    }

    public static void setBridgeLines(String bridgeLines) {
        OnionMasqJni.setBridgeLines(bridgeLines);
    }

    public static void setExcludedUids(long[] uids) {
        OnionMasqJni.setExcludedUids(uids);
    }

    public static ArrayList<Circuit> getCircuitsForAppUid(int appId) {
        return getInstance().circuitStore.getCircuitsForAppUid(appId);
    }

    public static ArrayList<CircuitCountryCodes> getCircuitCountryCodesForAppUid(int appId) {
        return getInstance().circuitStore.getCircuitCountryCodesForAppUid(appId);
    }
}
