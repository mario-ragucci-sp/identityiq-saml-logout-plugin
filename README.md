# saml-logout-plugin
## Why is there a need for such a plugin?
Once authentication is switched to SAML authentication, IdentityIQ removes the Logout button from the user menu. There is no point of having it there, since the authentication is done by the IdP, hence this session remains authenticated. Reopening IdentityIQ webpage will login the previously authenticated identity. While the proper solution is to have the user doing a logout on the IdP, this is usually hard to explain to the end user.
 
## How will it work?
The idea is to invalidate the IdentityIQ session and then to redirect to the IdP logout page. This way we make sure both sessions are invalidated, hence the user has to reauthenticate to IdP the next time she tries to access IdentityIQ.

### How do we do this?
There are several challenges to consider.
First, the required session index is only transmitted once, inside of the SAML authn Response. As the plugin is not involved in this process, we need to intercept the HTTP Request and get the required information
Second, we need to deal with multiple browser sessions (sadly).
Third, we need to store this information to make it available to the plugin.
 
For the first and second challenge, we will introduce a Filter that will get a member of the filter chain (defined in web.xml).
For the third task, we will create a small table in the identityiqPLugin database schema. This makes it easy to access information when the plugin generates the Logout Request.
 
### How does SLO work?
In short, each SAML session is identified by a session index. This information is transferred within the SAML authN response. To invalidate this session, a SAML LogoutRequest must be created that references to the session index.
The SAML provider will then respond with a SAML LogoutResponse, indicating either success of failure.
  
## Function of SamlSessionIndexFilter
I am not going to discuss the Filter in detail, but give  a rough explanation of what the Filter does.
The Filter, as it is part of the application filter chain, gets called on any request that is done against IdentityIQ. The Filter looks if the request contains a SAMLResponse.
If such a parameter is present, the Filter tries to lookup the SAML_SESSIONS table (by the query defined in the web.xml Filterconfiguration).
If the database exists, the filter gets the SAMLObject from the request and retrieves the required information (session index and the value of the attribute defined in the web.xml Filterdefinition) in combination with the CSRF token of this session.
The Information is stored in the database.

### Configuration of the SamlSessionIndexFilter
The session index is only available in the authN response of the IdP. Therefore, we need to create a ServletFilter that will intercept the authN response and store it - among other information - in a database.
The web.xml must be updated to contain the following definition. This will be the configuration for our SamlIndexSessionFilter.

```
<?xml version="1.0" encoding="utf-8"?>  
<filter>  
  <filter-name>SamlSessionIndexFilter</filter-name>  
  <filter-class>sailpoint.services.filter.SamlSessionIndexFilter</filter-class>  
  <!--  
  required settings  
  -->  
  <!-- The SAML assertion attribute that identifies the identity in IdentityIQ -->  
  <init-param>  
  <param-name>name-identifier</param-name>  
  <param-value>nameId</param-value>  
  </init-param>  
  <!-- SQL query that shall check whether the SAML_SESSIONS table exists at all -->  
  <init-param>  
  <param-name>sql-check-for-table-query</param-name>  
  <param-value>SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'identityiqPlugin' AND table_name = 'SAML_SESSIONS' LIMIT 1</param-value>  
  </init-param>  
  <!-- whether to use a Datasource of the Application server -->  
  <init-param>  
  <param-name>use-datasource</param-name>  
  <param-value>false</param-value>  
  </init-param>  
  <!--   
  set following params according to the setting of use-datasource  
  either set the datasource-name, or supply all information   
  requested by the parameters prefixed with sql  
  -->  
  <init-param>  
  <param-name>datasource-name</param-name>  
  <param-value>jdbc/identityPlugin</param-value>  
  </init-param>  
  <init-param>  
  <param-name>sql-jdbc-connection-string</param-name>  
  <param-value>jdbc:mysql://localhost/identityiqPlugin?useServerPrepStmts=true&amp;tinyInt1isBit=true&amp;useUnicode=true&amp;characterEncoding=utf8</param-value>  
  </init-param>  
  <init-param>  
  <param-name>sql-jdbc-driver</param-name>  
  <param-value>com.mysql.jdbc.Driver</param-value>  
  </init-param>  
  <init-param>  
  <param-name>sql-username</param-name>  
  <param-value>identityiqPlugin</param-value>  
  </init-param>  
  <init-param>  
  <param-name>sql-password</param-name>  
  <param-value>identityiqPlugin</param-value>  
  </init-param>  
</filter>  
<?xml version="1.0" encoding="utf-8"?>  
<filter-mapping>  
  <filter-name>SamlSessionIndexFilter</filter-name>  
  <url-pattern>/*</url-pattern>  
</filter-mapping>
```