package org.torproject.onionmasq.utils;

import java.text.SimpleDateFormat;
import java.util.Locale;

public class Utils {

    public static String getFormattedDate(long timestamp, Locale locale) {
        SimpleDateFormat sdf = new SimpleDateFormat("hh:mm:ss:SSS", locale);
        return sdf.format(timestamp);
    }

}
