# identityiq-saml-logout-plugin
## Why is there a need for such a plugin?

Once authentication is switched to SAML authentication, IdentityIQ removes the Logout button from the user menu. There is no point of having it there, since the authentication is done by the IdP, hence this session remains authenticated. Reopening IdentityIQ webpage will login the previously authenticated identity. While the proper solution is to have the user doing a logout on the IdP, this is usually hard to explain to the end user.

 
## How will it work?

The idea is to invalidate the IdentityIQ session and then to redirect to the IdP logout page. This way we make sure both sessions are invalidated, hence the user has to reauthenticate to IdP the next time she tries to access IdentityIQ.

This plugin will be based on the Plugin Framework shipped with IdentityIQ 7.1. With minor modifications, it should also work with IdentityIQ 7.0.

## Disclaimer

This documentation and its code is a proof of concept and probably not safe for use in your environment. Its intent is to show the possibilities the plugin framework offers rather than to provide a stable plugin for production usage.
