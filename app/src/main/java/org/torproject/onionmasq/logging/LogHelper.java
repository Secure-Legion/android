package org.torproject.onionmasq.logging;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.atomic.AtomicBoolean;

public class LogHelper {
    AtomicBoolean markInvalid = new AtomicBoolean(false);
    public void stopLog() {
        markInvalid.set(true);
    }

    public void readLog() {
        Thread t = new Thread(() -> {
                LogObservable.getInstance().addLog("Start reading onionmasq logs from logcat");
                String cmd = "logcat -v tag onionmasq:V StreamCapture:D *:S";
                try {
                    Runtime.getRuntime().exec("logcat -c");
                    Process process = Runtime.getRuntime().exec(cmd);
                    BufferedReader bufferedReader = new BufferedReader(
                            new InputStreamReader(process.getInputStream()));

                    String line = "";
                    while ((line = bufferedReader.readLine()) != null && !markInvalid.get()) {
                        LogObservable.getInstance().addLog(line);
                    }
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
                LogObservable.getInstance().addLog("Stop reading onionmasq logs from logcat");
        });
        t.start();
    }
}
