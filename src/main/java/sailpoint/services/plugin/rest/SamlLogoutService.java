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

import org.opensaml.common.SAMLObject;
import org.opensaml.ws.message.encoder.MessageEncodingException;

import sailpoint.api.SailPointContext;
import sailpoint.object.Attributes;
import sailpoint.object.Configuration;
import sailpoint.object.SAMLConfig;
import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.services.saml.ServicesSAMLConstant;
import sailpoint.tools.GeneralException;
import sailpoint.web.sso.SAMLUtil;

@Path("saml-logout")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.TEXT_PLAIN)
@AllowAll
public class SamlLogoutService extends BasePluginResource {
	public static final String SQL_SESSION_QUERY = "SELECT SESSION_INDEX FROM SAML_SESSIONS WHERE ACCOUNT=?";

	protected boolean isSamlEnabled=false;
    protected boolean signAuthN=false;


    protected String jksLocation=null;
    protected String jksPassword=null;
    protected String jksAlias=null;
    protected String storeType="JKS";
    
	@Override
	public String getPluginName() {
		return "saml-logout-plugin";
	}

	@GET
	@Path("doLogout")
	public String doLogout() {
		String redirectUrl = null;
		String sessionIndex = null;
		String principal = null;
		SAMLObject logoutRequest = null;
		boolean signRequest = getSettingBool("signRedirect");
		try {			
			principal = getLoggedInUserName();
			System.out.println(principal);
			sessionIndex = returnSessionIndexFromDb(principal);
			System.out.println(sessionIndex);
			SAMLConfig samlConfig = getSamlConfig();
			if(samlConfig != null) {
				logoutRequest = SAMLUtil.buildLogoutRequest(principal, samlConfig.getEntityId(), sessionIndex);
				if(signRequest) {
					setKeystoreInformation();
					sailpoint.services.x509key.JKSKeyManager jks =
	                        sailpoint.services.x509key.JKSKeyManager.getInstance(jksLocation,jksPassword,jksPassword,jksAlias,storeType);
					redirectUrl = SAMLUtil.buildSignedLogoutUrl(getSettingString("redirectUrl"), logoutRequest, jks.getDefaultCredential());				
				}else {
					redirectUrl = SAMLUtil.buildLogoutUrl(getSettingString("redirectUrl"), logoutRequest);
				}				
			}
			
		} catch (GeneralException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MessageEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		getSession().invalidate();
		return redirectUrl;
	}
	
	private void setKeystoreInformation() throws GeneralException {
		Configuration sysConfig = getContext().getConfiguration();
        this.isSamlEnabled = sysConfig.getBoolean(Configuration.SAML_ENABLED, false);
        this.signAuthN=sysConfig.getBoolean(ServicesSAMLConstant.CONFIG_SIGN_AUTHN, false);
        jksLocation=sysConfig.getString(ServicesSAMLConstant.CONFIG_SP_CERT);
        jksAlias=sysConfig.getString(ServicesSAMLConstant.CONFIG_SP_CERT_ALIAS);
        jksPassword=sysConfig.getString(ServicesSAMLConstant.CONFIG_SP_STORE_PASS);
        storeType=sysConfig.getString(ServicesSAMLConstant.CONFIG_SP_STORE_TYPE);
	}
	
	private SAMLConfig getSamlConfig() throws GeneralException {
		SailPointContext context = getContext();
		Configuration samlConfig = context.getObjectByName(Configuration.class, "SAML");
		Attributes<String,Object> attributes = samlConfig.getAttributes();
		
		SAMLConfig config = (SAMLConfig) attributes.get("IdentityNow");
		
		return config;
	}
	
	private String returnSessionIndexFromDb(String principal) throws GeneralException, SQLException {
		String result = null;
		Connection connection = getConnection();
		PreparedStatement prepStatement = connection.prepareStatement(SQL_SESSION_QUERY);
		
		prepStatement.setString(1, principal);
		
		ResultSet rs = prepStatement.executeQuery();
		if(rs.next()) {
			result = rs.getString(1);
		}
		
		rs.close();
		prepStatement.close();
		return result;
	}
}
