package sailpoint.services.plugin.rest;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;

@Path("saml-logout")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.TEXT_PLAIN)
@AllowAll
public class SamlLogoutService extends BasePluginResource {

	@Override
	public String getPluginName() {
		return "saml-logout-plugin";
	}

	@GET
	@Path("doLogout")
	public String doLogout() {
		getSession().invalidate();
		return this.getSettingString("redirectUrl");
	}
}
