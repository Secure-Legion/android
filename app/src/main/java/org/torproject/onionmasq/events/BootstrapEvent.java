package org.torproject.onionmasq.events;

import androidx.annotation.Nullable;

/**
 * An update on Arti bootstrapping status.
 */
public class BootstrapEvent extends OnionmasqEvent {
    /**
     * A vague progress percentage, from 0 to 100.
     */
    public int bootstrapPercent = 0;

    /**
     * A human-readable string detailing the bootstrap state.
     */
    public String bootstrapStatus;

    /**
     * If true, Arti is ready for us to pass traffic through it.
     */
    public boolean isReadyForTraffic = false;

    /**
     * An optional message detailing the reason why Arti is stuck.
     *
     * (If set, that obviously means the bootstrapping is stuck somehow.)
     */
    @Nullable
    public String blockageMessage;
}
