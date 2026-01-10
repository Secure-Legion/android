package org.torproject.onionmasq.errors;

/**
 * A RuntimeException for panics that occur in Rust code.
 */
public class RustPanicException extends RuntimeException {
    public RustPanicException(String message) {
        super(message);
    }
}
