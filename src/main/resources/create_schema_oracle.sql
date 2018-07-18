CREATE TABLE DB_KEY_STORE 
(
LABEL VARCHAR(255 CHAR) NOT NULL,
CIPHER_KEY CLOB,
CERT CLOB,
CHAIN CLOB,
KEYPASSWORD VARCHAR(256),
CREATED DATE
);

CREATE TABLE DB_KEY_STORE_METADATA
(
PROPERTY_KEY VARCHAR(255 CHAR) NOT NULL,
PROPERTY_VALUE CLOB
);


CREATE UNIQUE INDEX DB_KEY_STORE_PK_INDEX ON DB_KEY_STORE (LABEL);
ALTER TABLE DB_KEY_STORE ADD (
  CONSTRAINT DB_KEY_STORE_PK PRIMARY KEY (LABEL)
  USING INDEX DB_KEY_STORE_PK_INDEX
);

CREATE UNIQUE INDEX DB_KS_METADATA_PK_INDEX ON DB_KEY_STORE_METADATA (PROPERTY_KEY);
ALTER TABLE DB_KEY_STORE_METADATA ADD (
  CONSTRAINT DB_KEY_STORE_METADATA_PK PRIMARY KEY (PROPERTY_KEY)
  USING INDEX DB_KS_METADATA_PK_INDEX
);