/**
 * ©2018 – Gemalto – All Rights Reserved
 */
package com.gemalto.oss.crypto.db.keystore.exceptions;

/**
 * 
 * @author Jacek Szczukocki
 * @since 1.0
 */
public class DbKeyStoreRuntimeException extends RuntimeException {

    /**
     * UID.
     */
    private static final long serialVersionUID = -8929392322930864775L;

    public DbKeyStoreRuntimeException() {
        super();
    }

    public DbKeyStoreRuntimeException(String message) {
        super(message);
    }

    public DbKeyStoreRuntimeException(Throwable cause) {
        super(cause);
    }

    public DbKeyStoreRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public DbKeyStoreRuntimeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
