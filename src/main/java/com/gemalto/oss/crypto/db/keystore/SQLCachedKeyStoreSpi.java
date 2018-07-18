/**
 * ©2018 – Gemalto – All Rights Reserved
 */
package com.gemalto.oss.crypto.db.keystore;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gemalto.oss.crypto.db.keystore.exceptions.DbKeyStoreRuntimeException;

/**
 * This class defines the <i>Service Provider Interface</i> (<b>SPI</b>) for the
 * {@code KeyStore} class. This class is basis for {@code SQL} DataBase support
 * for {@code KeyStore}.
 *
 * @author Jacek Szczukocki
 * @author Jiri Stary
 *
 * @see KeyStore
 *
 * @since 1.0
 */
abstract class SQLCachedKeyStoreSpi extends KeyStoreSpi {

	/*
	 * logger for this class.
	 */
	private final static Logger LOGGER = LoggerFactory.getLogger(SQLCachedKeyStoreSpi.class);
	/*
	 * local storage {@code Map}.
	 */
	private Map<String, KeyStoreEntry> storage = new ConcurrentHashMap<>();
	/*
	 * table name regular expression.
	 */
	private static final String TABLE_NAME_REGEX = "[A-Za-z0-9\\.\\\"\\_]+";
	/*
	 * base64 value of slat.
	 */
	private String saltBase64;
	/*
	 * algorithm used to encrypt private data. Currently default Advanced Encryption
	 * Standard (AES).
	 */
	private static final String KEY_TYPE = "AES";

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
		/*
		 * Retrieving {@code KeyStoreEntry} from local storage.
		 */
		KeyStoreEntry entry = getEntryByAlias(alias);
		/*
		 * no entry found.
		 */
		if (entry == null) {
			LOGGER.trace("[KSSQL] No key for alias [" + alias + "] ");
			return null;
		}
		/*
		 * if key string is empty (base64 value) entry is corrupted.
		 */
		String keyString = entry.getCiperKey();
		if (isStringEmpty(keyString)) {
			LOGGER.trace("[KSSQL] No key for alias [" + alias + "] ");
			return null;
		}
		/*
		 * Retrieving salted HMAC Sha256 of password (UTF-8) and salt.
		 */
		String keyPass = entry.getKeyPassword();
		ObjectInputStream oos = null;
		try {
			LOGGER.trace("[KSSQL] Decrypting key for alias [" + alias + "] ");
			/*
			 * compare given password with stored value.
			 */
			if (compareKeyPass(password, keyPass)) {
				/*
				 * if values are the same. Retrieve and return {@code Key}.
				 */
				byte[] keyData = decryptWithPass(password, Base64.getDecoder().decode(keyString));
				oos = new ObjectInputStream(new ByteArrayInputStream(keyData));
				Key key = (Key) oos.readObject();
				LOGGER.trace("[KSSQL] Returning decrypted key for alias [" + alias + "] ");
				return key;
			} else {
				throw new IllegalArgumentException("Incorrect password for entry : [" + alias + "]");
			}
		} catch (Exception e) {
			throw new UnrecoverableKeyException(e.getMessage());
		} finally {
			if (oos != null)
				try {
					oos.close();
				} catch (IOException e) {
					throw new UnrecoverableKeyException(e.getMessage());
				}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Certificate[] engineGetCertificateChain(String alias) {
		/*
		 * Retrieving {@code KeyStoreEntry} for given alias.
		 */
		KeyStoreEntry entry = getEntryByAlias(alias);
		if (entry == null) {
			LOGGER.trace("[KSSQL] No certificate chain for alias [" + alias + "] ");
			return null;
		}
		if (isStringEmpty(entry.getChain())) {
			LOGGER.trace("[KSSQL] No certificate chain for alias [" + alias + "] ");
			return null;
		}
		/*
		 * Certificate chain is stored as base64 value of binary {@code
		 * ObjectInputStream}.
		 */
		byte[] cert = Base64.getDecoder().decode(entry.getChain());
		ObjectInputStream ois = null;
		Certificate[] chain = null;
		try {
			ois = new ObjectInputStream(new ByteArrayInputStream(cert));
			chain = (Certificate[]) ois.readObject();
			LOGGER.trace("[KSSQL] Certificate chain found for alias [" + alias + "] ");
			return chain;
		} catch (IOException | ClassNotFoundException e) {
			throw new DbKeyStoreRuntimeException(e);
		} finally {
			if (ois != null)
				try {
					ois.close();
				} catch (IOException e) {
					throw new DbKeyStoreRuntimeException(e);
				}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Certificate engineGetCertificate(String alias) {
		/*
		 * Retrieving {@code KeyStoreEntry} for given alias.
		 */
		KeyStoreEntry entry = getEntryByAlias(alias);
		if (entry == null) {
			LOGGER.trace("[KSSQL] No Certificate found for alias [" + alias + "] ");
			return null;
		}
		if (!isStringEmpty(entry.getCert())) {
			byte[] cert = Base64.getDecoder().decode(entry.getCert());
			CertificateFactory fact;
			try {
				fact = CertificateFactory.getInstance("x509");
				Certificate crt = fact.generateCertificate(new ByteArrayInputStream(cert));
				LOGGER.trace("[KSSQL] Certificate found. Lookup done in cert for alias [" + alias + "] ");
				return crt;
			} catch (CertificateException e) {
				throw new DbKeyStoreRuntimeException(e);
			}
		} else if (!isStringEmpty(entry.getChain())) {
			Certificate[] certs = engineGetCertificateChain(alias);
			LOGGER.trace("[KSSQL] Certificate found. Lookup done in chain for alias [" + alias + "] ");
			return certs[0];
		} else {
			LOGGER.trace("[KSSQL] No Certificate found for alias [" + alias + "] ");
			return null;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Date engineGetCreationDate(String alias) {
		/*
		 * Retrieving {@code KeyStoreEntry} for given alias.
		 */
		KeyStoreEntry entry = getEntryByAlias(alias);
		LOGGER.trace("[KSSQL] Get creation date for alias [" + alias + "] ");
		if (entry == null)
			return null;
		return entry.getCreated();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
			throws KeyStoreException {
		ByteArrayOutputStream baos = null;
		ObjectOutputStream oos = null;
		try {
			baos = new ByteArrayOutputStream();
			oos = new ObjectOutputStream(baos);
			oos.writeObject(key);
			engineSetKeyEntry(alias, encryptWithPass(password, baos.toByteArray()), chain);
			storeKeyPass(alias, password);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		} finally {
			if (baos != null)
				try {
					baos.close();
				} catch (IOException e) {
					throw new KeyStoreException(e);
				}
			if (oos != null)
				try {
					oos.close();
				} catch (IOException e) {
					throw new KeyStoreException(e);
				}
		}

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
		LOGGER.trace("[KSSQL] Setting keystore key entry for alias [" + alias + "]");
		try {
			String cipheredKey = Base64.getEncoder().encodeToString(key);

			KeyStoreEntry entry = new KeyStoreEntry();
			entry.setLabel(alias);
			entry.setCiperKey(cipheredKey);
			entry.setCreated(new Date());
			this.storage.put(alias, entry);

			if (chain != null) {
				storeCertificateChain(alias, chain);
			}
		} catch (Exception e) {
			throw new KeyStoreException(e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
		LOGGER.trace("[KSSQL] Setting keystore certificate entry for alias [" + alias + "]");

		String encodedCert;
		try {
			encodedCert = Base64.getEncoder().encodeToString(cert.getEncoded());
			if (engineContainsAlias(alias)) {
				if (engineIsKeyEntry(alias)) {
					throw new KeyStoreException("Existing entry is not a trusted certificate entry+ [" + alias + "]");
				}
				this.storage.get(alias).setCert(encodedCert);
			} else {
				KeyStoreEntry entry = new KeyStoreEntry();
				entry.setLabel(alias);
				entry.setCert(encodedCert);
				entry.setCreated(new Date());
				this.storage.put(alias, entry);
			}
		} catch (CertificateEncodingException e) {
			throw new KeyStoreException(e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void engineDeleteEntry(String alias) throws KeyStoreException {
		if (alias == null) {
			return;
		}
		LOGGER.trace("[KSSQL] Deleting keystore alias : " + alias);

		storage.remove(alias);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Enumeration<String> engineAliases() {
		LOGGER.trace("[KSSQL] Enumerating keystore aliases");
		Vector<String> vect = new Vector<>();
		vect.addAll(storage.keySet());
		return vect.elements();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean engineContainsAlias(String alias) {
		boolean result = false;
		if (alias != null) {
			result = storage.containsKey(alias);
		}
		LOGGER.trace("[KSSQL] Keystore contains alias [" + alias + "] ? Result = " + result);
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int engineSize() {
		int result = this.storage.size();
		LOGGER.trace("[KSSQL] Keystore size is [" + result + " ]");
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean engineIsKeyEntry(String alias) {
		boolean result = storage.get(alias) != null && !isStringEmpty(storage.get(alias).getCiperKey());
		LOGGER.trace("[KSSQL] is key entry at alias [" + alias + " ]  = " + result);
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean engineIsCertificateEntry(String alias) {
		KeyStoreEntry entry = storage.get(alias);
		boolean result = entry != null && !isStringEmpty(entry.getCert());
		LOGGER.trace("[KSSQL] is key entry at alias [" + alias + " ]  = " + result);

		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String engineGetCertificateAlias(Certificate cert) {
		if (cert == null) {
			return null;
		}

		final List<String> alias = new ArrayList<>();
		storage.values().stream().forEach(e -> {
			if (alias.size() == 0) {
				if (cert.equals(engineGetCertificate(e.getLabel()))) {
					alias.add(e.getLabel());
				}
			}
		});

		String result;
		if (alias.size() != 1) {
			result = null;
		} else {
			result = alias.get(0);
		}
		LOGGER.trace("[KSSQL] Certificate entry found at alias [" + result + " ] ");

		return result;

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void engineLoad(InputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		loadKeyStoreFromDB(prepareConnection(stream, password));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void engineStore(OutputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		storeKeyStoreToDB(connect(password));
	}

	/**
	 * Method stores base64 value of binary {@code ObjectOutputStream}. If alias or
	 * chain are null no changes are made.
	 * 
	 * @param alias
	 *            of the entry.
	 * @param chain
	 *            chain to be stored.
	 */
	private void storeCertificateChain(String alias, Certificate[] chain) {
		if (chain == null)
			return;
		ObjectOutputStream oos = null;
		ByteArrayOutputStream baos = null;
		try {
			baos = new ByteArrayOutputStream();
			oos = new ObjectOutputStream(baos);
			oos.writeObject(chain);
			String encodedChain = Base64.getEncoder().encodeToString(baos.toByteArray());
			KeyStoreEntry keyStoreEntry = storage.get(alias);
			if (keyStoreEntry != null) {
				LOGGER.trace("[KSSQL] Storing certificate chain with alias [" + alias + "]");
				keyStoreEntry.setChain(encodedChain);
			}
		} catch (IOException e) {
			throw new DbKeyStoreRuntimeException(e);
		} finally {
			if (baos != null)
				try {
					baos.close();
				} catch (IOException e) {
					throw new DbKeyStoreRuntimeException(e);
				}
			if (oos != null)
				try {
					oos.close();
				} catch (IOException e) {
					throw new DbKeyStoreRuntimeException(e);
				}
		}
	}

	/**
	 * 
	 * @param alias
	 * @param keypass
	 * @throws KeyStoreException
	 */
	private void storeKeyPass(String alias, char[] keypass) throws KeyStoreException {
		if (keypass == null)
			return;
		try {
			String encodedPass = saltedHmacSha256(new String(keypass).getBytes("UTF-8"), this.saltBase64);
			KeyStoreEntry keyStoreEntry = storage.get(alias);
			if (keyStoreEntry != null) {
				keyStoreEntry.setKeyPassword(encodedPass);
				LOGGER.trace("[KSSQL] Storing key password with alias [" + alias + "]");

			}
		} catch (Exception e) {
			throw new KeyStoreException(e);
		}
	}

	private boolean compareKeyPass(char[] password, String storedKeyPass) throws Exception {
		LOGGER.trace(String.format("Comparing key password [%s]:", password == null ? null : new String(password)));
		if (password == null && storedKeyPass == null) {
			LOGGER.trace("[KSSQL] Comparing key password with result:" + true);
			return true;
		}
		if ((password == null && storedKeyPass != null) || (password != null && storedKeyPass == null)) {
			LOGGER.trace("[KSSQL] Comparing key password with result:" + false);
			return false;
		}
		boolean result = (storedKeyPass.equals(saltedHmacSha256(new String(password).getBytes("UTF-8"), saltBase64)));
		LOGGER.trace("[KSSQL] Comparing key password with result:" + result);
		return result;
	}

	private static String saltedHmacSha256(byte[] key, String salt) throws Exception {
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
		sha256_HMAC.init(secret_key);
		return Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(Base64.getDecoder().decode(salt)));
	}

	private String generateSaltBase64() {
		SecureRandom random = new SecureRandom();
		byte[] data = new byte[256];
		random.nextBytes(data);
		return Base64.getEncoder().encodeToString(data);
	}

	private byte[] decryptWithPass(char[] password, byte[] data) throws KeyStoreException {
		if (password == null || password.length == 0)
			return data;

		return doCipher(password, data, Cipher.DECRYPT_MODE);

	}

	private byte[] encryptWithPass(char[] password, byte[] data) throws KeyStoreException {
		if (password == null || password.length == 0)
			return data;

		return doCipher(password, data, Cipher.ENCRYPT_MODE);

	}

	private byte[] doCipher(char[] password, byte[] data, int mode) throws KeyStoreException {
		try {
			SecureRandom rand = new SecureRandom(new String(password).getBytes("UTF-8"));
			byte[] passRand = new byte[16];
			byte[] initVector = new byte[16];
			rand.nextBytes(passRand);
			rand.nextBytes(initVector);

			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec secretKey = new SecretKeySpec(passRand, KEY_TYPE);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(mode, secretKey, iv);

			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new KeyStoreException(e);
		}
	}

	private KeyStoreEntry getEntryByAlias(String alias) {
		KeyStoreEntry entry;

		if (alias == null) {
			entry = null;
		} else {
			entry = storage.get(alias);
		}

		LOGGER.trace("[KSSQL] Getting keystore entry for alias [" + alias + "] with result: " + entry);

		return entry;
	}

	private String clobToString(Clob data) throws SQLException, IOException {
		if (data == null)
			return null;
		StringBuilder sb = new StringBuilder();
		Reader reader = data.getCharacterStream();
		BufferedReader br = new BufferedReader(reader);

		String line;
		while (null != (line = br.readLine())) {
			sb.append(line);
		}
		br.close();
		return sb.toString();
	}

	private Clob stringToClob(String data, Connection connection) throws SQLException {
		Clob clob = connection.createClob();
		if (data == null)
			return clob;
		clob.setString(1, data);
		return clob;
	}

	private void closeStatement(Statement statement) {
		if (statement != null)
			try {
				statement.close();
			} catch (SQLException e) {
				throw new DbKeyStoreRuntimeException(e);
			}
	}

	protected abstract Connection connect(char[] password);

	protected abstract Connection prepareConnection(InputStream stream, char[] password);

	protected abstract void closeConnection(Connection connection);

	protected abstract String getStorageTable();

	protected abstract String getMetaDataTable();

	private void storeKeyStoreToDB(Connection connection) throws IOException {
		String deleteQuery01 = "DELETE FROM " + getStorageTable();
		String deleteQuery02 = "DELETE FROM " + getMetaDataTable() + " WHERE PROPERTY_KEY = 'SALT'";
		String querySalt = "INSERT INTO " + getMetaDataTable() + " (PROPERTY_KEY, PROPERTY_VALUE) VALUES (?,?)";

		String insertRowQuery = "INSERT INTO " + getStorageTable()
				+ " (LABEL, CIPHER_KEY, CERT, CHAIN, KEYPASSWORD, CREATED) VALUES (?,?,?,?,?,?)";

		PreparedStatement pr = null;

		try {
			pr = connection.prepareStatement(deleteQuery01);
			pr.executeUpdate();
			closeStatement(pr);
			pr = connection.prepareStatement(deleteQuery02);
			pr.executeUpdate();
			closeStatement(pr);
			pr = connection.prepareStatement(querySalt);
			pr.setString(1, "SALT");
			pr.setClob(2, stringToClob(this.saltBase64, connection));
			pr.executeUpdate();
			closeStatement(pr);

			pr = connection.prepareStatement(insertRowQuery);
			for (KeyStoreEntry entry : this.storage.values()) {

				pr.setString(1, entry.getLabel());
				pr.setClob(2, stringToClob(entry.getCiperKey(), connection));
				pr.setClob(3, stringToClob(entry.getCert(), connection));
				pr.setClob(4, stringToClob(entry.getChain(), connection));
				pr.setString(5, entry.getKeyPassword());
				pr.setDate(6, new java.sql.Date(entry.getCreated().getTime()));

				pr.executeUpdate();
			}
		} catch (Exception e) {
			throw new IOException("Cannot store the keystore: ", e);
		} finally {
			closeStatement(pr);
			closeConnection(connection);
		}
	}

	private void loadKeyStoreFromDB(Connection connection) throws IOException {
		String query = "SELECT * FROM " + getStorageTable();
		String queryMetadata = "SELECT PROPERTY_VALUE FROM " + getMetaDataTable() + " WHERE PROPERTY_KEY = 'SALT'";
		this.storage = new ConcurrentHashMap<>();
		PreparedStatement pr01 = null;
		PreparedStatement pr02 = null;
		ResultSet rs = null;
		try {
			pr01 = connection.prepareStatement(query);
			rs = pr01.executeQuery();
			while (rs.next()) {
				KeyStoreEntry entry = new KeyStoreEntry();
				entry.setLabel(rs.getString("LABEL"));
				entry.setCiperKey(clobToString(rs.getClob("CIPHER_KEY")));
				entry.setCert(clobToString(rs.getClob("CERT")));
				entry.setChain(clobToString(rs.getClob("CHAIN")));
				entry.setKeyPassword(rs.getString("KEYPASSWORD"));
				entry.setCreated(rs.getDate("CREATED"));
				this.storage.put(entry.getLabel(), entry);
			}
			rs.close();

			pr02 = connection.prepareStatement(queryMetadata);
			rs = pr02.executeQuery();
			if (rs.next()) {
				this.saltBase64 = clobToString(rs.getClob("PROPERTY_VALUE"));
			}
			if (this.saltBase64 == null)
				this.saltBase64 = generateSaltBase64();
			rs.close();
		} catch (Exception e) {
			throw new IOException("Cannot load keystore from database: ", e);
		} finally {
			closeStatement(pr01);
			closeStatement(pr02);
			closeConnection(connection);
		}
	}

	protected String validateTableName(String property) {
		if (property.matches(TABLE_NAME_REGEX))
			return property;
		else
			throw new IllegalArgumentException(
					String.format("Table name %s does not match regex %s.", property, TABLE_NAME_REGEX));
	}

	private class KeyStoreEntry {

		private String label;
		private String ciperKey;
		private String cert;
		private String chain;
		private String keyPassword;
		private Date created;

		public KeyStoreEntry() {

		}

		public String getLabel() {
			return label;
		}

		public void setLabel(String label) {
			this.label = label;
		}

		public String getCiperKey() {
			return ciperKey;
		}

		public void setCiperKey(String ciperKey) {
			this.ciperKey = ciperKey;
		}

		public String getCert() {
			return cert;
		}

		public void setCert(String cert) {
			this.cert = cert;
		}

		public String getChain() {
			return chain;
		}

		public void setChain(String chain) {
			this.chain = chain;
		}

		public String getKeyPassword() {
			return keyPassword;
		}

		public void setKeyPassword(String keyPassword) {
			this.keyPassword = keyPassword;
		}

		public Date getCreated() {
			return created;
		}

		public void setCreated(Date created) {
			this.created = created;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			KeyStoreEntry other = (KeyStoreEntry) obj;
			return this.getLabel().equals(other.getLabel());
		}
	}

	private boolean isStringEmpty(String str) {
		return str == null || str.isEmpty();
	}

}
