/*
Create database schema and also authentication policy and assign it to account. What Suthentication you need to login in Snowflake
MFA_Enrollment states whether your account need MFA or not
 */
USE ROLE ACCOUNTADMIN;
create database dwh_prod;
create schema dwh_prod.auth_obj;
use dwh_prod.auth_obj;
CREATE or replace AUTHENTICATION POLICY require_mfa_authentication_policy
  AUTHENTICATION_METHODS = ('SAML')
  CLIENT_TYPES = ('SNOWFLAKE_UI', 'SNOWSQL', 'DRIVERS')
  MFA_AUTHENTICATION_METHODS = ( 'SAML')
  MFA_ENROLLMENT = REQUIRED;

alter account set authentication policy  require_mfa_authentication_policy;

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

  USE ROLE ACCOUNTADMIN;
CREATE SECURITY INTEGRATION AZUREADINTEGRATION
TYPE = SAML2
ENABLED = TRUE
SAML2_ISSUER = 'https://sts.windows.net/740d81d4-e4d6-4689-8d63-22257ff4a74c/' 
SAML2_SSO_URL = 'https://login.microsoftonline.com/740d81d4-e4d6-4689-8d63-22257ff4a74c/saml2'
SAML2_PROVIDER = 'CUSTOM'
SAML2_X509_CERT = ''<Base64 encoded IdP certificate>'
SAML2_SP_INITIATED_LOGIN_PAGE_LABEL = 'AzureADSSO'
SAML2_ENABLE_SP_INITIATED = TRUE;


desc integration AZUREADINTEGRATION;
ALTER SECURITY INTEGRATION AZUREADINTEGRATION SET SAML2_SNOWFLAKE_ACS_URL = 'https://vfwpowd-wg85018.snowflakecomputing.com/fed/login';

ALTER SECURITY INTEGRATION AZUREADINTEGRATION SET SAML2_SNOWFLAKE_ISSUER_URL = 'https://vfwpowd-wg85018.snowflakecomputing.com';

/*
Create 1 more integration for SCIM (System for cross domain identity management)
this will help to provision adn deprovision the user from ENtra ID .
 */

create or replace role aad_provisioning;
grant create user on account to role aad_provisioning;
grant role aad_provisioning to role accountadmin;

create or replace security integration aad_provisioning
    type = scim
    scim_client = 'azure'
    run_as_role = 'AAD_PROVISIONING';
select system$generate_scim_access_token('AAD_PROVISIONING');





