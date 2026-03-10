# nextgen_authn_api 
Database setup :

MySQL Server Installation using Homebrew :

Install MySQL server using homwbrew

brew install mysql

Start the server with below command

brew services start mysql

Install MySql Workbench

Install Workbench from https://dev.mysql.com/downloads/workbench/

Add a new connection in Workbench local instance on port local, set the password and test Connection

Commands to create Database and tables

Create Database:

CREATE DATABASE webauthn_db;
USE webauthn_db;
Create Database User table
CREATE TABLE  users(
id bigint NOT NULL AUTO_INCREMENT,
display_name varchar(255) DEFAULT NULL,
user_handle varchar(255) NOT NULL,
username varchar(255) NOT NULL,
PRIMARY KEY (id),
UNIQUE KEY  (user_handle),
UNIQUE KEY (username)
) ;

Create Credential table:

CREATE TABLE credentials (
id bigint NOT NULL AUTO_INCREMENT,
aaguid varchar(255) DEFAULT NULL,
attested_credential_data longblob,
authenticator_type varchar(255) DEFAULT NULL,
credential_id varchar(255) NOT NULL,
public_key longblob,
sign_count bigint NOT NULL,
user_id bigint NOT NULL,
PRIMARY KEY (id),
UNIQUE KEY (credential_id),
CONSTRAINT FOREIGN KEY (user_id) REFERENCES users (id)
);

Verify the created tables:

select * from users;

select * from credentials;

    Or 

SELECT * FROM webauthn_db.users;

SELECT * FROM webauthn_db.credentials;