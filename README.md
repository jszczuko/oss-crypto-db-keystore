[![N|Solid](https://www.gemalto.com/_catalogs/masterpage/Gemalto/assets/logo-gemalto-340x120.gif)](https://www.gemalto.com)

# DBKeyStore

This package provides functionality to use [KeyStore](https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html) with support of SQL database by implementing [KeyStoreSpi](https://docs.oracle.com/javase/7/docs/api/java/security/KeyStoreSpi.html) support of jdbc connection, both by jdbc url and jndi datasource lookup.

# Registring security provider.

To add the provider at runtime use:

```java
import java.security.Security;
import com.gemalto.oss.crypto.db.keystore.DbProvider;
    
Security.addProvider(new DbProvider());
```
The provider can also be configured as part of your environment via static registration by adding an entry to the java.security properties file (found in $JAVA_HOME/jre/lib/security/java.security, where $JAVA_HOME is the location of your JDK/JRE distribution). You'll find detailed instructions in the file but basically it comes down to adding a line:
```java
security.provider.<n>=com.gemalto.oss.crypto.db.keystore.DbProvider
```
Where < n > is the preference you want the provider at (1 being the most preferred).

# DataBase schema

Schema pre prepared for hsqldb database can be created by executing:

``` sql
CREATE TABLE DB_KEY_STORE 
(
    LABEL VARCHAR(255) NOT NULL,
    CIPHER_KEY CLOB,
    CERT CLOB,
    CHAIN CLOB,
    KEYPASSWORD VARCHAR(256),
    CREATED DATE
);

CREATE TABLE DB_KEY_STORE_METADATA
(
    PROPERTY_KEY VARCHAR(255) NOT NULL,
    PROPERTY_VALUE CLOB
);

ALTER TABLE DB_KEY_STORE ADD PRIMARY KEY (LABEL);
ALTER TABLE DB_KEY_STORE_METADATA ADD PRIMARY KEY (PROPERTY_KEY);
```

# Loading KeyStore

```java
Properties prop = new Properties();
prop.setProperty("connection.class", "org.hsqldb.jdbc.JDBCDriver");
prop.setProperty("connection.url", "jdbc:hsqldb:file:target/testDb");
prop.setProperty("connection.username", "user_name");
prop.setProperty("store.table", "DB_KEY_STORE");
prop.setProperty("metadata.table", "DB_KEY_STORE_METADATA");
ByteArrayOutputStream output = new ByteArrayOutputStream();
prop.store(output, null);
ByteArrayInputStream input = new ByteArrayInputStream(output.toByteArray());

ks = KeyStore.getInstance(DbProvider.DB_KS, DbProvider.PROVIDER_NAME);
ks.load(input, "database_password".toCharArray());
```

# Encryption schema

Private keys will be stored in encrypted form using AES/CBC/PKCS5PADDING cipher.


# Package dependencie
```xml
<dependencies>
  <dependency>
    <groupId>com.gemalto.oss.crypto</groupId>
    <artifactId>db-keystore</artifactId>
    <version>0.2.2</version>
  </dependency>
</dependencies>

```