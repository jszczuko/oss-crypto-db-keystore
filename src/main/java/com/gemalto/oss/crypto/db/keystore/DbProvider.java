/**
 * ©2018 – Gemalto – All Rights Reserved
 */
package com.gemalto.oss.crypto.db.keystore;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.gemalto.oss.crypto.db.keystore.exceptions.DbKeyStoreRuntimeException;

/**
 * This class provides functionality to use {@link KeyStore} with support of
 * database.<br>
 * To add the provider at runtime use:
 * 
 * <pre>
 * import java.security.Security;
 * import com.gemalto.oss.crypto.db.keystore.DbProvider;
 *
 * Security.addProvider(new DbProvider());
 * </pre>
 * 
 * The provider can also be configured as part of your environment via static
 * registration by adding an entry to the java.security properties file (found
 * in $JAVA_HOME/jre/lib/security/java.security, where $JAVA_HOME is the
 * location of your JDK/JRE distribution). You'll find detailed instructions in
 * the file but basically it comes down to adding a line:
 * 
 * <pre>
 * <code>
 *    security.provider.&lt;n&gt;=com.gemalto.oss.crypto.db.keystore.DbProvider
 * </code>
 * </pre>
 * 
 * Where &lt;n&gt; is the preference you want the provider at (1 being the most
 * preferred).
 *
 * @author Jacek Szczukocki
 * @version 1.0
 */
public class DbProvider extends Provider {

	private static final String KEY_STORE = "KeyStore";

	private static final String ALGO = "algo";

	public static final String DB_KS = "DbKS";

	public static final String DS_KS = "DsKS";

	public static final double version = 1.0;

	public static final String PROVIDER_NAME = "DbKSProvider";

	private static final String info = "Database keystore v" + version;

	/**
	 * UID.
	 */
	private static final long serialVersionUID = -5458217546595904943L;

	private List<Service> services = new ArrayList<>();

	/**
	 * Construct a new provider. This should only be required when using runtime
	 * registration of the provider using the <code>Security.addProvider()</code>
	 * mechanism.
	 */
	public DbProvider() {
		super(PROVIDER_NAME, Double.toString(version), info);
		this.services.add(new DbKeyStoreService(this, DB_KS, ALGO, DbKeyStoreService.class.getName(), null, null));
		this.services.add(new DbKeyStoreService(this, DS_KS, ALGO, DbKeyStoreService.class.getName(), null, null));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized Service getService(String type, String algorithm) {
		if (KEY_STORE.equals(type) && DB_KS.equals(algorithm)) {
			return this.services.get(0);
		}
		if (KEY_STORE.equals(type) && DS_KS.equals(algorithm)) {
			return this.services.get(1);
		}

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized Set<Service> getServices() {
		return new HashSet<>(this.services);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Object get(Object key) {
		throw new DbKeyStoreRuntimeException();
	}

	public class DbKeyStoreService extends Service {

		public DbKeyStoreService(Provider provider, String type, String algorithm, String className,
				List<String> aliases, Map<String, String> attributes) {
			super(provider, type, algorithm, className, aliases, attributes);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
			if (DB_KS.equals(this.getType()))
				return new DbKeyStoreSpi();
			if (DS_KS.equals(this.getType()))
				return new DsKeyStoreSpi();
			return null;

		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public boolean supportsParameter(Object parameter) {
			throw new DbKeyStoreRuntimeException();
		}

	}

}
