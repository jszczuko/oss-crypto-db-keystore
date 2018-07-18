/**
 * ©2018 – Gemalto – All Rights Reserved
 */
package com.gemalto.oss.crypto.db.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

import com.gemalto.oss.crypto.db.keystore.exceptions.DbKeyStoreRuntimeException;

/**
 * 
 * 
 * @author Jacek Szczukocki
 * 
 * @see SQLCachedKeyStoreSpi
 * 
 * @since 1.0
 *
 */
public class DbKeyStoreSpi extends SQLCachedKeyStoreSpi {

	private String connectionClass;
	private String connectionUrl;
	private String connectionUsername;
	private String storeTable;
	private String metadataTable;

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Connection connect(char[] password) {
		try {
			Class.forName(connectionClass);
			Connection connection = DriverManager.getConnection(connectionUrl, connectionUsername,
					new String(password));
			connection.setAutoCommit(true);
			return connection;
		} catch (ClassNotFoundException | SQLException e) {
			throw new DbKeyStoreRuntimeException(e);
		}

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Connection prepareConnection(InputStream stream, char[] password) {

		try {
			Properties properties = new Properties();
			properties.load(stream);

			this.connectionClass = properties.getProperty("connection.class");
			this.connectionUrl = properties.getProperty("connection.url");
			this.connectionUsername = properties.getProperty("connection.username");
			this.storeTable = properties.containsKey("store.table")
					? validateTableName(properties.getProperty("store.table"))
					: "DB_KEY_STORE";
			this.metadataTable = properties.containsKey("metadata.table")
					? validateTableName(properties.getProperty("metadata.table"))
					: "DB_KEY_STORE_METADATA";

			return connect(password);
		} catch (IOException e) {
			throw new DbKeyStoreRuntimeException(e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void closeConnection(Connection connection) {
		if (connection != null)
			try {
				if (!connection.isClosed())
					connection.close();
			} catch (SQLException e) {
				throw new DbKeyStoreRuntimeException(e);
			}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getStorageTable() {
		return this.storeTable;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getMetaDataTable() {
		return this.metadataTable;
	}

}
