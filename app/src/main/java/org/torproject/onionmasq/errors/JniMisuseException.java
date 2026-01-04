package org.torproject.onionmasq.errors;

/**
 * An exception raised when a Rust->Java JNI call fails for some reason.
 * This usually (but not always) indicates some form of programming error.
 */
public class JniMisuseException extends RuntimeException {

    public JniMisuseException(String message) {
        super(message);
    }
}
