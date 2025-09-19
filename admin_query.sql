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
SAML2_ISSUER = 'https://sts.windows.net/<azure tenantid>/' 
SAML2_SSO_URL = 'https://login.microsoftonline.com/<azure tenantid>/saml2'
SAML2_PROVIDER = 'CUSTOM'
SAML2_X509_CERT = '<X509Certificate>'
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
