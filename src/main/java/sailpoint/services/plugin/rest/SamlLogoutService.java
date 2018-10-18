package sailpoint.services.plugin.rest;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.log4j.Logger;
import org.opensaml.common.SAMLObject;
import org.opensaml.ws.message.encoder.MessageEncodingException;

import sailpoint.api.SailPointContext;
import sailpoint.object.Attributes;
import sailpoint.object.Configuration;
import sailpoint.object.SAMLConfig;
import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.services.saml.ServicesSAMLConstant;
import sailpoint.services.util.SAMLUtil;
import sailpoint.tools.GeneralException;

@Path("saml-logout")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.TEXT_PLAIN)
@AllowAll
public class SamlLogoutService extends BasePluginResource {
	public static final String SQL_SESSION_QUERY = "SELECT SESSION_INDEX FROM SAML_SESSIONS WHERE ACCOUNT=? AND CSRF_TOKEN=?";
	public static final String SQL_REMOVE_DATA	 = "DELETE FROM SAML_SESSIONS WHERE ACCOUNT=? AND CSRF_TOKEN=?";
	public static final Logger _logger = Logger.getLogger(SamlLogoutService.class);
	
	protected boolean isSamlEnabled	= false;
    protected boolean signAuthN		= false;

    protected String jksLocation	= null;
    protected String jksPassword	= null;
    protected String jksAlias		  = null;
    protected String storeType    = "JKS";
    
	@Override
	public String getPluginName() {
		return "saml_logout_plugin";
	}

	@GET
	@Path("doLogout")
	public String doLogout() {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s()", "doLogout"));
		}
		
		boolean signRequest 	 	    = getSettingBool("signRedirect");
		boolean createLogoutRequest	= getSettingBool("createLogoutRequest");
		String redirectUrl 		 	    = getSettingString("redirectUrl");		
		
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("redirectURL: %s, createLogoutRequest: %s, signRequest: %s",
					redirectUrl, createLogoutRequest, signRequest));
		}
		
		if(createLogoutRequest) {
			String sessionIndex 	 	  = null;
			String principal 		 	    = null;
			String csrfToken			    = null;
			SAMLObject logoutRequest 	= null;
			
			try {	
				principal = getLoggedInUserName();
				csrfToken = getCsrfToken();
				sessionIndex = returnSessionIndexFromDb(principal, csrfToken);
				SAMLConfig samlConfig = getSamlConfig();
				
				if(samlConfig != null) {
					String entityId = samlConfig.getEntityId();
					if(entityId == null) {
						throw new GeneralException("entityID could not be retrieved from SAML Configuration");
					}
					logoutRequest = SAMLUtil.buildLogoutRequest(principal, entityId, sessionIndex);
					
					if(signRequest) {
						setKeystoreInformation();
						if(!validateKeystoreInformation()) {
							throw new GeneralException("Important Configuration Elements are missing. Were the SAML enhancements installed?");
						}
						
						// Build signed logout URL
						sailpoint.services.x509key.JKSKeyManager jks =
		                        sailpoint.services.x509key.JKSKeyManager.getInstance(jksLocation,jksPassword,jksPassword,jksAlias,storeType);
						redirectUrl = SAMLUtil.buildSignedLogoutUrl(redirectUrl, logoutRequest, jks.getDefaultCredential());				
					}else {
						// Build reqular logout URL
						redirectUrl = SAMLUtil.buildLogoutUrl(redirectUrl, logoutRequest);
					}
					// Remove entry from db
					removeEntryFromDb(principal, csrfToken);
				} else {
					throw new GeneralException("no SAMLConfig could be retrieved from the database. Please review your SAML configuration");
				}
			} catch (GeneralException e) {
				_logger.error(e.getMessage(), e);
			} catch (SQLException e) {
				_logger.error(e.getMessage(), e);
			} catch (MessageEncodingException e) {
				_logger.error(e.getMessage(), e);
			}
		}
		
		// Invalidate session and return URL
		getSession().invalidate();
		
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "doLogout", redirectUrl));
		}
		return redirectUrl;
	}
	
	/**
	 * Returns the csrf token of the session
	 * @return
	 */
	private String getCsrfToken() {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s()", "getCsrfToken"));
		}
		String csrfToken = (String) getSession().getAttribute("csrfToken");
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "getCsrfToken", csrfToken));
		}
		return csrfToken;
	}

	/**
	 * @return
	 */
	private boolean validateKeystoreInformation() {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s()", "validateKeystoreInformation"));
		}
		boolean result = false;
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("jksLocation: %s, jksAlias: %s, jksPassword: %s, storeType: %s", 
					jksLocation, jksAlias, jksPassword, storeType));
		}
		result = (jksLocation != null && !jksLocation.isEmpty()) ? true : false;
		result = (jksAlias    != null && !jksAlias.isEmpty())    ? true : false;
		result = (jksPassword != null && !jksPassword.isEmpty()) ? true : false;
		result = (storeType   != null && !storeType.isEmpty())   ? true : false;
		
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "validateKeystoreInformation", result));
		}
		
		return result;
	}
	
	/**
	 * @throws GeneralException
	 */
	private void setKeystoreInformation() throws GeneralException {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s()", "setKeystoreInformation"));
		}
		Configuration sysConfig;
		sysConfig		= getContext().getConfiguration();
        isSamlEnabled 	= sysConfig.getBoolean(Configuration.SAML_ENABLED, false);
        signAuthN		    = sysConfig.getBoolean(ServicesSAMLConstant.CONFIG_SIGN_AUTHN, false);
        jksLocation		  = sysConfig.getString(ServicesSAMLConstant.CONFIG_SP_CERT);
        jksAlias		    = sysConfig.getString(ServicesSAMLConstant.CONFIG_SP_CERT_ALIAS);
        jksPassword		  = sysConfig.getString(ServicesSAMLConstant.CONFIG_SP_STORE_PASS);
        String strType  = sysConfig.getString(ServicesSAMLConstant.CONFIG_SP_STORE_TYPE);        
        storeType       = (strType != null && !strType.isEmpty())? strType : storeType;
        
        if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "setKeystoreInformation", "void"));
		}
	}
	
	/**
	 * Returns the IdentityIQ SAML Configuration object
	 * @return the SAMLConfig object
	 * @throws GeneralException
	 */
	private SAMLConfig getSamlConfig() throws GeneralException {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s()", "getSamlConfig"));
		}
		SailPointContext context = getContext();
		Configuration samlConfig = context.getObjectByName(Configuration.class, "SAML");
		Attributes<String,Object> attributes = samlConfig.getAttributes();
		
		SAMLConfig config = (SAMLConfig) attributes.get("IdentityNow");
		
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "getSamlConfig", config));
		}
		return config;
	}
	
	/**
	 * returns a session index from the database
	 * @param principal the name of the logged-in account
	 * @param csrfToken the csrf token associated to the session
	 * @return
	 * @throws GeneralException
	 * @throws SQLException
	 */
	private String returnSessionIndexFromDb(String principal, String csrfToken) throws GeneralException, SQLException {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s(principal = %s, csrfToken)", "returnSessionIndexFromDb", principal, csrfToken));
		}
		String result = null;
		Connection connection = getConnection();
		PreparedStatement prepStatement = connection.prepareStatement(SQL_SESSION_QUERY);
		
		prepStatement.setString(1, principal);
		prepStatement.setString(2, csrfToken);
		
		ResultSet rs = prepStatement.executeQuery();
		if(rs.next()) {
			result = rs.getString(1);
		}
		
		rs.close();
		prepStatement.close();
		connection.close();
		
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "returnSessionIndexFromDb", result));
		}
		return result;
	}
	
	/**
	 * removes a session index from the database
	 * @param principal the name of the logged-in account
	 * @param csrfToken the csrf token associated to the session
	 * @throws GeneralException
	 * @throws SQLException
	 */
	private void removeEntryFromDb(String principal, String csrfToken) throws GeneralException, SQLException {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s(principal = %s, csrfToken)", "removeEntryFromDb", principal, csrfToken));
		}
		Connection connection = getConnection();
		PreparedStatement prepStatement = connection.prepareStatement(SQL_REMOVE_DATA);
		
		prepStatement.setString(1, principal);
		prepStatement.setString(2, csrfToken);
		
		prepStatement.execute();

		prepStatement.close();
		connection.close();
		
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "removeEntryFromDb", "void"));
		}
	}
}
