package org.torproject.onionmasq.logging;

import android.os.Looper;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class LogObservable extends ViewModel {

    private final MutableLiveData<LinkedList<LogItem>> logListData;
    private static LogObservable instance;
    private boolean reverseOrder = false;
    private int maxCapacity = 1000;
    private final Object LOCK = new Object();

    private LogObservable() {
        logListData = new MutableLiveData<>(new LinkedList<>());
    }

    public static LogObservable getInstance() {
        if (instance == null) {
            instance = new LogObservable();
        }
        return instance;
    }

    public void setReverseOrder(boolean isReverse) {
        synchronized (LOCK) {
            if (this.reverseOrder == isReverse) {
                return;
            }
            this.reverseOrder = isReverse;
            LinkedList<LogItem> list = logListData.getValue();
            if (list == null || list.isEmpty()) {
                return;
            }
            Collections.reverse(list);
            setList(list);
        }
    }

    public void addLog(String log) {
        synchronized (LOCK) {
            LinkedList<LogItem> list = logListData.getValue();
            if (list == null) {
                return;
            }
            if (reverseOrder) {
                list.addFirst(new LogItem(System.currentTimeMillis(), log));
                if (list.size() > maxCapacity) {
                    list.removeLast();
                }
            } else {
                list.add(new LogItem(System.currentTimeMillis(), log));
                if (list.size() > maxCapacity) {
                    list.removeFirst();
                }
            }
            setList(list);
        }
    }

    public void setCapacity(int maxCapacity) throws IllegalArgumentException {
        synchronized (LOCK) {
            if (maxCapacity < 1) {
                throw new IllegalArgumentException("The log list capacity must be >= 1");
            }
            this.maxCapacity = maxCapacity;
            LinkedList<LogItem> list = logListData.getValue();
            if (list != null && list.size() > maxCapacity) {
                List<LogItem> subList = reverseOrder ?
                        new LinkedList<>(list.subList(maxCapacity, list.size())) :
                        new LinkedList<>(list.subList(0, list.size() - maxCapacity));
                list.removeAll(subList);
            }
            setList(list);
        }
    }

    public String getLogStrings(boolean showTimestamp) {
        StringBuilder builder = new StringBuilder();
        LinkedList<LogItem> logItemArrayList = getLogList();
        if (logItemArrayList == null) {
            return "";
        }
        for (LogItem item : logItemArrayList) {
            builder.append(item.toString(showTimestamp)).append("\n");
        }
        return builder.toString();
    }

    /**
     * Use this method to observe changes of the list. In order to access the list, use @method getLogList() afterwards.
     * @return LiveData containing the List of LogItems
     */
    public LiveData<LinkedList<LogItem>> getLiveData() {
        return logListData;
    }

    /**
     * Getter method to access the LogItems in a thread safe manner.
     * @return a copy of the list of LogItems
     */
    public LinkedList<LogItem> getLogList() {
        synchronized (LOCK) {
            LinkedList<LogItem> logItemList = logListData.getValue();
            if (logItemList == null) {
                return new LinkedList<>();
            }
            return new LinkedList<>(logItemList);
        }
    }

    public void clearLogs() {
        synchronized (LOCK) {
            setList(new LinkedList<>());
        }
    }

    private void setList(LinkedList<LogItem> list) {
        if (Looper.getMainLooper().getThread() == Thread.currentThread()) {
            logListData.setValue(list);
        } else {
            logListData.postValue(list);
        }
    }
}