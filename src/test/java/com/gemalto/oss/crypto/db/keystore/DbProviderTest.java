package com.gemalto.oss.crypto.db.keystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class DbProviderTest {

	private static final String KS_PASSWORD = "KS_PASSWORD";
	private static final String KS_USER = "KS_USER";
	protected static KeyStore ks = null;
	private static String fileName = "kstest";

	@BeforeClass
	public static void setUp() throws IOException, CertificateException, NoSuchAlgorithmException,
			NoSuchProviderException, KeyStoreException, SQLException {
		Security.addProvider(new DbProvider());

		prepare();

		Properties prop = new Properties();
		prop.setProperty("connection.class", "org.hsqldb.jdbc.JDBCDriver");
		prop.setProperty("connection.url", "jdbc:hsqldb:file:target/" + fileName);
		prop.setProperty("connection.username", KS_USER);
		prop.setProperty("store.table", "DB_KEY_STORE");
		prop.setProperty("metadata.table", "DB_KEY_STORE_METADATA");

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		prop.store(output, null);
		ByteArrayInputStream input = new ByteArrayInputStream(output.toByteArray());

		ks = KeyStore.getInstance(DbProvider.DB_KS, DbProvider.PROVIDER_NAME);
		assertNotNull(ks);
		ks.load(input, KS_PASSWORD.toCharArray());
	}

	@AfterClass
	public static void setDown() throws SQLException {
		delete();
	}

	@Test
	public void testStoreKeyStoreTest()
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		ks.store(null, KS_PASSWORD.toCharArray());
	}

	@Test
	public void testGetKeyStoreSingleKey() throws KeyStoreException, NoSuchProviderException, IOException,
			NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		KeyPair pair = keyGen.generateKeyPair();
		PublicKey pub = pair.getPublic();
		try {
			int initialSize = ks.size();
			ks.setKeyEntry("test01", pub, null, null);
			Key key01 = ks.getKey("test01", null);

			assertNotNull(key01);
			assertEquals(1, ks.size() - initialSize);
			assertTrue(ks.isKeyEntry("test01"));
		} finally {
			ks.deleteEntry("test01");
		}

	}

	@Test
	public void testGetKeyStoreSingleKeyWithPassword() throws KeyStoreException, NoSuchProviderException, IOException,
			NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		KeyPair pair = keyGen.generateKeyPair();
		PublicKey pub = pair.getPublic();

		try {
			int initialSize = ks.size();
			ks.setKeyEntry("test02", pub, "some very very strange password".toCharArray(), null);
			Key key02 = ks.getKey("test02", "some very very strange password".toCharArray());

			assertNotNull(key02);
			assertEquals(1, ks.size() - initialSize);
			assertTrue(ks.isKeyEntry("test02"));
		} finally {
			ks.deleteEntry("test02");
		}

	}

	@Test(expected = UnrecoverableKeyException.class)
	public void testGetKeyStoreSingleKeyWithInvalidPassword() throws KeyStoreException, NoSuchProviderException,
			IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		KeyPair pair = keyGen.generateKeyPair();
		PublicKey pub = pair.getPublic();

		try {
			ks.setKeyEntry("test02", pub, "password".toCharArray(), null);
			ks.getKey("test02", "invalid_password".toCharArray());
		} finally {
			ks.deleteEntry("test02");
		}

	}

	@Test
	public void testPasswordDecryption() throws KeyStoreException, NoSuchProviderException, IOException,
			NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		char[] password = "some very very strange password".toCharArray();
		byte[] data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes();

		// encrypt
		SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
		rand.setSeed(new String(password).getBytes("UTF-8"));
		byte[] passRand = new byte[16];
		byte[] initVector = new byte[16];
		rand.nextBytes(passRand);
		rand.nextBytes(initVector);

		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec secretKey = new SecretKeySpec(passRand, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

		byte[] cyphertext = cipher.doFinal(data);

		// decrypt
		rand = SecureRandom.getInstance("SHA1PRNG");
		rand.setSeed(new String(password).getBytes("UTF-8"));
		passRand = new byte[16];
		initVector = new byte[16];
		rand.nextBytes(passRand);
		rand.nextBytes(initVector);

		iv = new IvParameterSpec(initVector);
		secretKey = new SecretKeySpec(passRand, "AES");
		cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
		byte[] doFinal = cipher.doFinal(cyphertext);
		Assert.assertArrayEquals(data, doFinal);
	}

	@Test
	public void testGetKeyCert() throws KeyStoreException, NoSuchProviderException, IOException,
			NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();

		BufferedInputStream bis = null;
		InputStream certStream = null;

		try {
			certStream = DbProviderTest.class.getClassLoader().getResourceAsStream("1024b-dsa-example-cert.der");
			bis = new BufferedInputStream(certStream);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Certificate cert = cf.generateCertificate(bis);
			ks.setCertificateEntry("test03", cert);
			assertTrue(ks.isCertificateEntry("test03"));
			Certificate cert01 = ks.getCertificate("test03");
			assertNotNull(cert01);
			ks.deleteEntry("test03");

			ks.setKeyEntry("test04", priv, "test".toCharArray(), new Certificate[] { cert });
			Certificate[] certs = ks.getCertificateChain("test04");
			ks.store(null, KS_PASSWORD.toCharArray());
			assertNotNull(certs);
			ks.deleteEntry("test04");
		} finally {
			bis.close();
			certStream.close();
		}

	}

	@Test
	public void testGetKeyStoreMultipleEntries() throws KeyStoreException, NoSuchProviderException, IOException,
			NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();

		try {
			int initialSize = ks.size();
			
			String password = "some very very strange password";

			ks.setKeyEntry("test01", pub, null, null);
			ks.setKeyEntry("test02", pub, password.toCharArray(), null);

			Key key01 = ks.getKey("test01", null);
			Key key02 = ks.getKey("test02", password.toCharArray());

			assertNotNull(key01);
			assertNotNull(key02);
			assertEquals(2, ks.size() - initialSize);
			assertTrue(ks.isKeyEntry("test01"));
			assertTrue(ks.isKeyEntry("test02"));
		} finally {
			ks.deleteEntry("test01");
			ks.deleteEntry("test02");
		}

		InputStream certStream = null;
		BufferedInputStream bis = null;

		try {
			certStream = DbProviderTest.class.getClassLoader().getResourceAsStream("1024b-dsa-example-cert.der");
			bis = new BufferedInputStream(certStream);

			CertificateFactory cf = CertificateFactory.getInstance("X.509");

			Certificate cert = cf.generateCertificate(bis);
			ks.setCertificateEntry("test03", cert);
			assertTrue(ks.isCertificateEntry("test03"));
			Certificate cert01 = ks.getCertificate("test03");
			assertNotNull(cert01);
			ks.deleteEntry("test03");

			ks.setKeyEntry("test04", priv, "test".toCharArray(), new Certificate[] { cert });
			Certificate[] certs = ks.getCertificateChain("test04");
			assertNotNull(certs);
			ks.deleteEntry("test04");
		} finally {
			certStream.close();
			bis.close();
		}
	}

	private static void prepare() throws SQLException {
		Connection connection = DriverManager.getConnection("jdbc:hsqldb:file:target/" + fileName, KS_USER,
				KS_PASSWORD);
		Statement statement = connection.createStatement();
		statement.execute(
				"CREATE TABLE DB_KEY_STORE (LABEL VARCHAR(255) NOT NULL, CIPHER_KEY CLOB, CERT CLOB, CHAIN CLOB, KEYPASSWORD VARCHAR(256), CREATED DATE);");

		statement.execute(
				"CREATE TABLE DB_KEY_STORE_METADATA ( PROPERTY_KEY VARCHAR(255) NOT NULL, PROPERTY_VALUE CLOB );");
		connection.commit();
		statement.execute("ALTER TABLE DB_KEY_STORE ADD PRIMARY KEY (LABEL);");

		statement.execute("ALTER TABLE DB_KEY_STORE_METADATA ADD PRIMARY KEY (PROPERTY_KEY);");
		connection.commit();

		connection.close();
	}

	private static void delete() throws SQLException {
		Connection connection = DriverManager.getConnection("jdbc:hsqldb:file:target/" + fileName, KS_USER,
				KS_PASSWORD);
		Statement statement = connection.createStatement();
		statement.execute("DROP TABLE DB_KEY_STORE;");
		statement.execute("DROP TABLE DB_KEY_STORE_METADATA;");
		connection.commit();

		connection.close();
	}

}
