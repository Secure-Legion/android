package org.torproject.onionmasq.utils;

import android.util.Log;

import androidx.annotation.WorkerThread;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class OnionmasqThreadpoolExecutor extends ThreadPoolExecutor {
    private static final String TAG = OnionmasqThreadpoolExecutor.class.getSimpleName();
    public static final long TASK_DEBOUNCE_TIME = 500L;
    private long debounceTime = TASK_DEBOUNCE_TIME;
    private long terminationTimeout = 3000L;

    public OnionmasqThreadpoolExecutor() {
        super(1,1,1000, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(2), new ThreadPoolExecutor.DiscardOldestPolicy());
    }

    public OnionmasqThreadpoolExecutor(long debounceTime) {
        super(1,1,1000, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(2), new ThreadPoolExecutor.DiscardOldestPolicy());
        this.debounceTime = debounceTime;
    }


    public OnionmasqThreadpoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue, RejectedExecutionHandler handler) {
        super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue, handler);
    }

    public void setTerminationTimeout(long milliseconds) {
        this.terminationTimeout = milliseconds;
    }

    @Override
    public Future<?> submit(Runnable task) {
        return super.submit(new CombinedRunnable(task, this::debounce));
    }

    /**
     * Lets the worker thread (which is part of a limited thread pool) sleep.
     * The respective executor service the worker thread belongs to filters out the oldest pending
     * task from it's execution queue. Because of this rejection strategy and the limited queue size
     * waiting on a worker thread after it did its job causes to debounce tasks that are
     * submitted repeatedly and quickly after each other.
     */
    @WorkerThread
    private void debounce() {
        try {
            Thread.sleep(this.debounceTime);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void shutdown() {
        Log.d(TAG, "Stopping ExecutorService");
        super.shutdown();
    }

    /**
     * Blocking call which rejects any new submitted tasks returns after the executed task has been finished.
     */
    public void awaitTermination() {
        // wait until current task has finished or timeout as reached
        boolean finished = false;
        try {
            finished = awaitTermination(terminationTimeout, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            Log.d(TAG, finished ? "ExecutorService stopped" : "Timeout stopping ExecutorService");
        }
    }

    public static final class CombinedRunnable implements Runnable
    {
        private final Runnable first;
        private final Runnable second;

        public CombinedRunnable(Runnable first, Runnable second)
        {
            this.first = first;
            this.second = second;
        }

        @Override
        public void run()
        {
            first.run();
            second.run();
        }
    }
}
