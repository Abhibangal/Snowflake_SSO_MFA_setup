/*
Create database schema and also authentication policy and assign it to account. What Suthentication you need to login in Snowflake
MFA_Enrollment states whether your account need MFA or not
 */
USE ROLE ACCOUNTADMIN;
create database dwh_prod;
create schema dwh_prod.auth_obj;
use dwh_prod.auth_obj;
--=======================================================================================================================
--Create database schema and also authentication policy and assign it to account. What Authentication you need to login in Snowflake
--MFA_Enrollment states whether your account need MFA or not
-- Precedence of authentication policy is User level -override-> Account Level.
--=======================================================================================================================
CREATE or replace AUTHENTICATION POLICY require_mfa_authentication_policy
  AUTHENTICATION_METHODS = ('SAML')
  CLIENT_TYPES = ('SNOWFLAKE_UI', 'SNOWSQL', 'DRIVERS')
  MFA_AUTHENTICATION_METHODS = ( 'SAML')
  MFA_ENROLLMENT = REQUIRED;

  alter account set authentication policy  require_mfa_authentication_policy;
--=======================================================================================================================
-- Breakglass user and authentication for it is MUST .If Identity provider faces any outage and then there will be now way
-- Any user can login ,not even user with ACCOUNTADMIN role 
-- So i this scenario a special USER only for contingency should have authentication with only PASSWORD.
-- Make sure you store passowrd in KEy VAULT with limited access.
-- Assign breakglass_accountadmin with password only authentication policy
--=======================================================================================================================
CREATE AUTHENTICATION POLICY ACCOUNTADMIN_BREAKGLASS_MFA
  AUTHENTICATION_METHODS = ('PASSWORD')
  MFA_AUTHENTICATION_METHODS = ('PASSWORD') -- enforce Snowflake MFA for native passwords only
  MFA_ENROLLMENT = 'REQUIRED';


create or replace user breakglass_accountadmin
email = '<recoverymail>'
default_role = accountadmin
Password = '<passowrd>';

grant role accountadmin to user breakglass_accountadmin; 
alter user breakglass_accountadmin set authentication policy ACCOUNTADMIN_BREAKGLASS_MFA;
--=======================================================================================================================
/*
Create a Securtiy integration using SAML(Security Assertion Markup Language) this is for authentication 
Service provide is Snowflake 
Identity provider  - Microsoft Entra ID , OKTa, Duo
Change the snowflake acs url and issuer url as gave in Microsoftr entra enterpsri user as SNowfalke SSO 
NOTE
/*
The above values can all be found in the XML Federation Metadata file, where: 

X509Certificate
entityID in format https://sts.windows.net/[...]/ (include the trailing forward slash).
Location in format https://login.microsoftonline.com/[...]/saml2
Where:

SAML2_X509_CERT: Only include the certificate body, in one single line, wrapped in single quotes, without BEGIN or END tags.
SAML2_SSO_URL: Login URL in the Azure portal (Location in the XML file)
SAML2_PROVIDER: Accepted values are OKTA, ADFS or CUSTOM. Use CUSTOM when AzureAD is the IdP.
SAML2_ISSUER: Azure AD Identifier value (EntityID)
 */
--======================================================================================================================

USE ROLE ACCOUNTADMIN;
CREATE SECURITY INTEGRATION AZUREADINTEGRATION
TYPE = SAML2
ENABLED = TRUE
SAML2_ISSUER = 'https://sts.windows.net/740d81d4-e4d6-4689-8d63-22257ff4a74c/' 
SAML2_SSO_URL = 'https://login.microsoftonline.com/740d81d4-e4d6-4689-8d63-22257ff4a74c/saml2'
SAML2_PROVIDER = 'CUSTOM'
SAML2_X509_CERT = 'MIIC8DCCAdigAwIBAgIQFXz6/wAlMKJO5vojKUCB6zANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNTA5MTMxNjUxNTJaFw0yODA5MTMxNjUxNTFaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwcRgQhqZE8++nHuiCFsvEEsild8jZPtiADU+b9roW2FXmEOKnpAD7Cwim5/l0PmPU+/UvdpWPHZpDedb53wONcmq7cvgQ+GkarySIGKkou17iBdN5r1JQ8vz5dUEKnLwvG/ZuTj86Gew7zUOhPViSFdDCnIGYPMEQVUoCVRQAa04BuUnKwusCEPFa+EZ1aXD9fq3Lx9+2eDAGJduVHE/HWqeGcstvAcZ+RzSnNMyx2B6f3JQ7S1/HNXYkC1AsEfJhs2Z6KBdA89gw8z/reRFa9u0ZQjSb+5ZecL5sD2qjZrsMtn4R66b3CsE8PeWsom0O5FIw6rrkT5mwVFkRYYWVQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAVHdg/QmtTzLVPlidSbpLLdZmpnyuEDplvU3Yek6teSLOz9nk5vP6M6qO9s+gWmWjTeVKK3oMYDyOfs30ACJlbeHjIz16Dj0HFcKnC2licsDXbMT3kwf6QbMGqikjojtSmv4rIFBAj8hYkJL0RU4qKMfyOzje4gO1ZcLR/kE20e477kpMEDbR88wIS63ce2zEBg5O4BbvmKd1qsjJH/3RUPzY0J/3wh/IP8zmeG1o6PMyL6pC/TLvPNnyIsscpSpyyt5mOYL97yQz4H3oRyOB3heK2Z97uzF2fWGj3WCD1s00/Jrmk4vT8pEdrh40h+Ixw+0ZSkCS/IY3lutI+2YTP'
SAML2_SP_INITIATED_LOGIN_PAGE_LABEL = 'AzureADSSO'
SAML2_ENABLE_SP_INITIATED = TRUE;


desc integration AZUREADINTEGRATION;
ALTER SECURITY INTEGRATION AZUREADINTEGRATION SET SAML2_SNOWFLAKE_ACS_URL = 'https://<orgname-accountname>.snowflakecomputing.com/fed/login';

ALTER SECURITY INTEGRATION AZUREADINTEGRATION SET SAML2_SNOWFLAKE_ISSUER_URL = 'https://<orgname-accountname>.snowflakecomputing.com';
--=======================================================================================================================

/*
Create 1 more integration for SCIM (System for cross domain identity management)
this will help to provision adn deprovision the user from ENtra ID .

TENANT ID WILL be - 'https://<orgname-accountname>.snowflakecomputing.com/scim/v2'
credential will be getting from select system$generate_scim_access_token('AAD_PROVISIONING'); query
 */
--=======================================================================================================================
create or replace role aad_provisioning;
grant create user on account to role aad_provisioning;
grant role aad_provisioning to role accountadmin;

create or replace security integration aad_provisioning
    type = scim
    scim_client = 'azure'
    run_as_role = 'AAD_PROVISIONING';
select system$generate_scim_access_token('AAD_PROVISIONING');
--=======================================================================================================================
-- Create authentication policy for Accountadmin.
-- Why coz accountadmin should have 2 authentication method enable SAML and Password both.
-- IN Case Identity provider faces any outage Accountadmin can set the MINS_TO_BYPASS_MFA for user and user can login 
-- using password.
-- Assign only 2 high privileged users .
--=======================================================================================================================

CREATE AUTHENTICATION POLICY ACCOUNTADMIN_DOUBLE_MFA
  AUTHENTICATION_METHODS = ('PASSWORD', 'SAML')
  SECURITY_INTEGRATIONS = ('AZUREADINTEGRATION')
  MFA_AUTHENTICATION_METHODS = ('PASSWORD', 'SAML') -- double MFA
  MFA_ENROLLMENT = 'REQUIRED';


alter user <username1> set authentication policy ACCOUNTADMIN_DOUBLE_MFA;
alter user <username1> set authentication policy ACCOUNTADMIN_DOUBLE_MFA; 
--=======================================================================================================================
--=======================================================================================================================