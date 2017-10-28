// does an Ajax Request to our RESTful logout service and evaluates 
// the answer in order to do a browser redirect
function doSamlLogout(url) {
    Ext.Ajax.request({
        url: url,
        success: function(response){
            window.location.assign(response.responseText);
        }
    });
}

jQuery(document).ready(function() {    
    // URL where we will find our RESTful logout service    
    var samlLogoutUrl = SailPoint.CONTEXT_PATH + '/plugin/rest/saml-logout/doLogout';

    // 'Magic Code' to have a logout button appear
    jQuery("ul.navbar-right li:last").after(
    '<li role="presentation"><a href="#" id="samlLogoutLink" role="menuitem" tabindex="0" onclick="doSamlLogout(\''+samlLogoutUrl+'\');">' +
    '<i class="fa fa-sign-out m-r-xs" role="presentation" aria-hidden="true"></i>SAML-Logout</a>'+
    '</li>');    

});