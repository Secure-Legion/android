package org.torproject.onionmasq;

import androidx.annotation.Nullable;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BridgeLineParser {
    private static final String TAG = BridgeLineParser.class.getSimpleName();

    static class BridgeConfig {
        private String fingerprint;
        private String host;
        HashMap<String, String> bridgeLineOptions = new HashMap<>();
        private String bridgeLine;

        private boolean parseOption(@Nullable String param, String option) {
            if (param == null) {
                return false;
            }
            if (param.startsWith(option)) {
                bridgeLineOptions.put(option, param.strip().substring((option+"=").length()));
                return true;
            }
            return false;
        }

        private void parseOptions(@Nullable String param, Set<String> options) {
            for (String option : options) {
                if (parseOption(param, option)) return;
            }
        }
    }
    public static class IPtConfig {
        private final String bridgeType;

        private final ArrayList<BridgeConfig> bridgeConfigs = new ArrayList<>();
        private int selectedBridgeConfig = 0;

        private long ptClientPort = -1;

        public IPtConfig(String bridgeType) {
            this.bridgeType = bridgeType;
        }

        private void parseBridgeConfigOptions(Matcher matcher, Set<String> options) {
            BridgeConfig bridgeConfig = new BridgeConfig();
            bridgeConfig.bridgeLine = matcher.group(0);
            bridgeConfig.host = matcher.group(1);
            bridgeConfig.fingerprint = matcher.group(2);

            for (int i = 3; i <= matcher.groupCount(); i++) {
                String param = matcher.group(i);
                bridgeConfig.parseOptions(param, options);
            }
            bridgeConfigs.add(bridgeConfig);
        }

        public void setPtClientPort(long ptClientPort) {
            this.ptClientPort = ptClientPort;
        }

        public long getPtClientPort() {
            return ptClientPort;
        }

        public ArrayList<BridgeConfig> getBridgeConfigs() {
            return bridgeConfigs;
        }

        public void selectSingleBridgeConfig() {
            if (bridgeConfigs.isEmpty()) {
                return;
            }
            SecureRandom random = new SecureRandom();
            selectedBridgeConfig = random.nextInt(bridgeConfigs.size());
        }

        public String getSelectedBridgeLine() {
            try {
                return bridgeConfigs.get(selectedBridgeConfig).bridgeLine;
            } catch (ArrayIndexOutOfBoundsException | NullPointerException ignore) {}
            return null;
        }

        public String getBridgeType() {
            return bridgeType;
        }

        public String getOption(String option) {
            try {
                return bridgeConfigs.get(selectedBridgeConfig).bridgeLineOptions.get(option);
            } catch (ArrayIndexOutOfBoundsException | NullPointerException ignore) {}
            return null;
        }

        public String getBridgeLines() {
            if (bridgeConfigs.isEmpty()) {
                return null;
            }
            if (SNOWFLAKE.equals(bridgeType)) {
                return getSelectedBridgeLine();
            }
            StringBuilder stringBuilder = new StringBuilder();
            for (BridgeConfig bridgeConfig : bridgeConfigs) {
                stringBuilder.append(bridgeConfig.bridgeLine).append("\n");
            }
            return stringBuilder.toString().trim();
        }
    }

    public static final String CERT = "cert";
    public static final String IAT_MODE = "iat-mode";
    public static final String OBFS4 = "obfs4";
    public static final String SNOWFLAKE = "snowflake";
    public static final String FINGERPRINT = "fingerprint";
    public static final String URL = "url";
    public static final String FRONTS = "fronts";
    public static final String ICE = "ice";
    public static final String UTLS_IMITATE = "utls-imitate";
    public static final String AMP_CACHE = "amp-cache";
    public static final String SQS_QUEUE_URL = "sqs-queue-url";
    public static final String SQS_CREDS_STR = "sqs-creds-str";
    public static final String WEBTUNNEL = "webtunnel";
    public static final String VER="ver";

    public static final HashSet<String> obfs4Options = new HashSet<>(Arrays.asList(CERT, IAT_MODE));
    public static final HashSet<String> snowflakeOptions = new HashSet<>(Arrays.asList(FINGERPRINT, URL, ICE, FRONTS, UTLS_IMITATE, AMP_CACHE, SQS_CREDS_STR, SQS_CREDS_STR));
    public static final HashSet<String> webtunnelOptions = new HashSet<>(Arrays.asList(URL, VER));

    private static final Pattern obfs4Regex = Pattern.compile("^obfs4\\s+(\\S+)\\s+(\\S+)(?:"+
            addStringParameter(CERT)+
            addIntParameter(IAT_MODE)+
            ")*\\s*$");
    private static final Pattern snowflakeRegex = Pattern.compile("^snowflake\\s+(\\S+)\\s+(\\S+)(?:"+
            addStringParameter(FINGERPRINT)+
            addStringParameter(URL)+
            addListParameter(FRONTS)+
            addListParameter(ICE)+
            addStringParameter(AMP_CACHE)+
            addStringParameter(SQS_CREDS_STR)+
            addStringParameter(SQS_QUEUE_URL)+
            addStringParameter(UTLS_IMITATE)+
            ")*\\s*$");

    private static final Pattern webtunnelRegex = Pattern.compile("^webtunnel\\s+(\\S+)(?:\\s+([A-Za-z0-9]+))?(?:" +
                    addStringParameter(URL) +
                    addStringParameter(VER) +
                    ")*\\s*$");


    private static String addStringParameter(String key) {
        return "(?:\\s+("+ key +"=\\S+))?";
    }

    private static String addIntParameter(String key) {
        return "(?:\\s+(" + key + "=\\d))?";
    }

    private static String addListParameter(String key) {
        return "(?:\\s+("+ key +"=[^\\s]+(?:,[^\\s]+)*))?";
    }
    public static void parseBridgeLine(String bridgeLine, HashMap<String, IPtConfig> typeConfigsMap) throws IllegalArgumentException {
        Matcher obfs4Matcher = obfs4Regex.matcher(bridgeLine);

        if (obfs4Matcher.matches()) {
            IPtConfig iptConfig = typeConfigsMap.getOrDefault(OBFS4, new IPtConfig(OBFS4));
            iptConfig.parseBridgeConfigOptions(obfs4Matcher, obfs4Options);
            typeConfigsMap.put(iptConfig.getBridgeType(), iptConfig);
            return;
        }

        Matcher snowflakeMatcher = snowflakeRegex.matcher(bridgeLine);
        if (snowflakeMatcher.matches()) {
            IPtConfig iptConfig = typeConfigsMap.getOrDefault(SNOWFLAKE, new IPtConfig(SNOWFLAKE));
            iptConfig.parseBridgeConfigOptions(snowflakeMatcher, snowflakeOptions);
            typeConfigsMap.put(iptConfig.getBridgeType(), iptConfig);
            return;
        }

        Matcher webtunnelMatcher = webtunnelRegex.matcher(bridgeLine);
        if (webtunnelMatcher.matches()) {
            IPtConfig iptConfig = typeConfigsMap.getOrDefault(WEBTUNNEL, new IPtConfig(WEBTUNNEL));
            iptConfig.parseBridgeConfigOptions(webtunnelMatcher, webtunnelOptions);
            typeConfigsMap.put(iptConfig.getBridgeType(), iptConfig);
            return;
        }
        throw new IllegalArgumentException("Bridge line could not be parsed.");
    }

    public static IPtConfig getIPtConfigFrom(String bridgeLines) {
        if (bridgeLines == null) {
            return null;
        }

        // 1. parse bridge lines
        String[] lines = bridgeLines.split("\n");
        HashMap<String, IPtConfig> bridgeTypeConfigsMap = new HashMap<>();
        for (String line: lines) {
            try {
                parseBridgeLine(line, bridgeTypeConfigsMap);
            } catch (IllegalArgumentException e) {
                e.printStackTrace();
            }
        }

        // 2. check result and randomize if we have multiple transport types parsed, since we can only
        // either handle snowflake or obfs4 as underlying obfuscation layer
        int index = 0;
        if (bridgeTypeConfigsMap.size() == 0) {
            return null;
        } else if (bridgeTypeConfigsMap.size() > 1){
            // we have more than 1 bridge type, let's randomize which type of bridgelines to use
            SecureRandom random = new SecureRandom();
            index = random.nextInt(bridgeTypeConfigsMap.size());
        }

        Object[] keys = bridgeTypeConfigsMap.keySet().toArray();
        String key = (String) keys[index];
        IPtConfig config = bridgeTypeConfigsMap.get(key);

        // 3. select only one bridge configuration in case of snowflake, since IPtProxy can - in contrast to obfs4 -
        // only handle one snowflake configuration
        if (config != null && SNOWFLAKE.equals(config.getBridgeType())) {
            config.selectSingleBridgeConfig();
        }
        return config;
    }
}
