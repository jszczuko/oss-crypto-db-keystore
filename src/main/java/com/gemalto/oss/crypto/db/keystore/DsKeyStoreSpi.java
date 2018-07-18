/**
 * ©2018 – Gemalto – All Rights Reserved
 */
package com.gemalto.oss.crypto.db.keystore;

import java.io.InputStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import com.gemalto.oss.crypto.db.keystore.exceptions.DbKeyStoreRuntimeException;

/**
 * 
 * @author Jacek Szczukocki
 * 
 * @see SQLCachedKeyStoreSpi
 * 
 * @since 1.0
 *
 */
public class DsKeyStoreSpi extends SQLCachedKeyStoreSpi {

	private DataSource dataSource;
	private String storeTable;
	private String metadataTable;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Connection connect(char[] password) {
		try {
			if (dataSource == null) {
				throw new IllegalStateException("DataSource not available");
			}
			return this.dataSource.getConnection();
		} catch (SQLException e) {
			 throw new RuntimeException(e);
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

			Context ctx = new InitialContext();
			this.dataSource = (DataSource) ctx.lookup(properties.getProperty("datasource.lookup"));

			this.storeTable = properties.containsKey("store.table")
					? validateTableName(properties.getProperty("store.table")) : "DB_KEY_STORE";
			this.metadataTable = properties.containsKey("metadata.table")
					? validateTableName(properties.getProperty("metadata.table")) : "DB_KEY_STORE_METADATA";
			
			return connect(password);
		} catch (Exception e) {
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
				connection.close();
			} catch (SQLException e) {

			}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getStorageTable() {
		return storeTable;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getMetaDataTable() {
		return metadataTable;
	}

}
