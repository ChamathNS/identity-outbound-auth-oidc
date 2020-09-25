package org.wso2.carbon.identity.application.authenticator.oidc.model;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import io.asgardio.java.oidc.sdk.config.OIDCConfigProvider;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

public class AuthenticationContextBasedOIDCConfigProvider implements OIDCConfigProvider {

    private static final Logger logger = LogManager.getLogger(AuthenticationContextBasedOIDCConfigProvider.class);

    private final OIDCAgentConfig config = new OIDCAgentConfig();

    public AuthenticationContextBasedOIDCConfigProvider(AuthenticationContext context)
            throws ApplicationAuthenticatorException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        ClientID clientID = StringUtils.isNotBlank(authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID)) ?
                new ClientID(authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID)) : null;
        Secret clientSecret =
                StringUtils.isNotBlank(authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET)) ?
                        new Secret(authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET)) : null;
        Scope scope = new Scope(OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE);
        try {
            URI callbackUrl =
                    StringUtils.isNotBlank(
                            authenticatorProperties.get(OIDCAuthenticatorConstants.IdPConfParams.CALLBACK_URL)) ?
                            new URI(authenticatorProperties
                                    .get(OIDCAuthenticatorConstants.IdPConfParams.CALLBACK_URL)) : null;
            URI tokenEndpoint =
                    StringUtils.isNotBlank(
                            authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL)) ?
                            new URI(authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL)) :
                            null;
            URI authorizeEndpoint =
                    StringUtils.isNotBlank(
                            authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL)) ?
                            new URI(authenticatorProperties
                                    .get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL)) : null;
            URI logoutEndpoint =
                    StringUtils.isNotBlank(
                            authenticatorProperties.get(OIDCAuthenticatorConstants.IdPConfParams.OIDC_LOGOUT_URL)) ?
                            new URI(authenticatorProperties
                                    .get(OIDCAuthenticatorConstants.IdPConfParams.OIDC_LOGOUT_URL)) : null;

            config.setConsumerKey(clientID);
            config.setConsumerSecret(clientSecret);
            config.setScope(scope);
            config.setCallbackUrl(callbackUrl);
            config.setTokenEndpoint(tokenEndpoint);
            config.setAuthorizeEndpoint(authorizeEndpoint);
            config.setLogoutEndpoint(logoutEndpoint);
            config.setPostLogoutRedirectURI(callbackUrl);
        } catch (URISyntaxException e) {
            logger.error("Exception while reading URIs for the authenticator.", e);
            throw new ApplicationAuthenticatorException(e.getMessage(), e);
        }
    }

    @Override
    public OIDCAgentConfig getOidcAgentConfig() {

        return config;
    }
}
