/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.oidc;

import com.nimbusds.jose.util.JSONObjectUtils;
import io.asgardio.java.oidc.sdk.OIDCManager;
import io.asgardio.java.oidc.sdk.OIDCManagerImpl;
import io.asgardio.java.oidc.sdk.bean.AuthenticationInfo;
import io.asgardio.java.oidc.sdk.bean.User;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;
import io.asgardio.java.oidc.sdk.exception.SSOAgentException;
import io.asgardio.java.oidc.sdk.exception.SSOAgentServerException;
import net.minidev.json.JSONArray;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.oidc.model.AuthenticationContextBasedOIDCConfigProvider;
import org.wso2.carbon.identity.application.authenticator.oidc.model.OIDCStateInfo;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OpenIDConnectAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4154255583070524018L;

    private static final Log log = LogFactory.getLog(OpenIDConnectAuthenticator.class);
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    private static final String DYNAMIC_PARAMETER_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static Pattern pattern = Pattern.compile(DYNAMIC_PARAMETER_LOOKUP_REGEX);

    @Override
    protected void processLogoutResponse(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) {

        log.debug("Handled logout response from service provider " + request.getParameter("sp") +
                " in tenant domain " + request.getParameter("tenantDomain"));
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isTraceEnabled()) {
            log.trace("Inside OpenIDConnectAuthenticator.canHandle()");
        }
        if (OIDCAuthenticatorConstants.LOGIN_TYPE.equals(getLoginType(request))) {
            return true;
        }

        // TODO : What if IdP failed?

        return false;
    }

    /**
     * @return
     */
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        return null;
    }

    /**
     * Returns the callback URL of the IdP Hub.
     *
     * @param authenticatorProperties Authentication properties configured in OIDC federated authenticator
     *                                configuration.
     * @return Callback URL configured in OIDC federated authenticator configuration. If it is empty returns
     * /commonauth endpoint URL path as the default value.
     */
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        String callbackUrl = authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        if (StringUtils.isBlank(callbackUrl)) {
            callbackUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        }
        return callbackUrl;
    }

    protected String getLogoutUrl(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(OIDCAuthenticatorConstants.IdPConfParams.OIDC_LOGOUT_URL);
    }

    /**
     * Returns the token endpoint of OIDC federated authenticator
     *
     * @param authenticatorProperties Authentication properties configured in OIDC federated authenticator
     *                                configuration.
     * @return Token endpoint configured in OIDC federated authenticator configuration.
     */
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
    }

    /**
     * @param state
     * @return
     */
    protected String getState(String state, Map<String, String> authenticatorProperties) {

        return state;
    }

    /**
     * @return
     */
    protected String getScope(String scope, Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(scope)) {
            scope = OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE;
        }
        return scope;
    }

    /**
     * @return
     */
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {

        return true;
    }

    /**
     * @param context
     * @param oidcClaims
     * @param oidcResponse
     * @return
     */

    protected String getAuthenticateUser(AuthenticationContext context, Map<String, Object> oidcClaims,
                                         OAuthClientResponse oidcResponse) {

        return (String) oidcClaims.get(OIDCAuthenticatorConstants.Claim.SUB);
    }

    protected String getCallBackURL(Map<String, String> authenticatorProperties) {

        return getCallbackUrl(authenticatorProperties);
    }

    protected String getQueryString(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(FrameworkConstants.QUERY_PARAMS);
    }

    /**
     * Get user info endpoint.
     *
     * @param token                   OAuthClientResponse
     * @param authenticatorProperties Map<String, String> (Authenticator property, Property value)
     * @return User info endpoint.
     */
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
    }

    /**
     * Get subject attributes.
     *
     * @param token                   OAuthClientResponse
     * @param authenticatorProperties Map<String, String> (Authenticator property, Property value)
     * @return Map<ClaimMapping, String> Claim mappings.
     */
    protected Map<ClaimMapping, String> getSubjectAttributes(OAuthClientResponse token,
                                                             Map<String, String> authenticatorProperties) {

        Map<ClaimMapping, String> claims = new HashMap<>();

        try {
            String accessToken = token.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);
            String url = getUserInfoEndpoint(token, authenticatorProperties);
            String json = sendRequest(url, accessToken);

            if (StringUtils.isBlank(json)) {
                if (log.isDebugEnabled()) {
                    log.debug("Empty JSON response from user info endpoint. Unable to fetch user claims." +
                            " Proceeding without user claims");
                }
                return claims;
            }

            Map<String, Object> jsonObject = JSONUtils.parseJSON(json);

            for (Map.Entry<String, Object> data : jsonObject.entrySet()) {
                String key = data.getKey();
                Object valueObject = data.getValue();

                if (valueObject != null) {
                    String value;
                    if (valueObject instanceof Object[]) {
                        value = StringUtils.join((Object[]) valueObject, FrameworkUtils.getMultiAttributeSeparator());
                    } else {
                        value = valueObject.toString();
                    }
                    claims.put(ClaimMapping.build(key, key, null, false), value);
                }

                if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)
                        && jsonObject.get(key) != null) {
                    log.debug("Adding claims from end-point data mapping : " + key + " - " + jsonObject.get(key)
                            .toString());
                }
            }
        } catch (IOException e) {
            log.error("Communication error occurred while accessing user info endpoint", e);
        }

        return claims;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String sessionState = getStateParameter(context, authenticatorProperties);
            OIDCAgentConfig config = new AuthenticationContextBasedOIDCConfigProvider(context).getOidcAgentConfig();

            OIDCManager oidcManager = new OIDCManagerImpl(config);
            oidcManager.sendForLogin(request, response, sessionState);

        } catch (IOException | ApplicationAuthenticatorException | SSOAgentClientException e) {
            log.error("Exception while sending to the login page", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    private String getStateParameter(AuthenticationContext context, Map<String, String> authenticatorProperties) {

        String state = context.getContextIdentifier() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
        return getState(state, authenticatorProperties);
    }

    private String getOIDCAuthzEndpoint(Map<String, String> authenticatorProperties) {

        String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
        if (StringUtils.isBlank(authorizationEP)) {
            authorizationEP = authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        }
        return authorizationEP;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            OIDCAgentConfig config = new AuthenticationContextBasedOIDCConfigProvider(context).getOidcAgentConfig();
            OIDCManager oidcManager = new OIDCManagerImpl(config);
            AuthenticationInfo authenticationInfo = oidcManager.handleOIDCCallback(request, response);
            User user = authenticationInfo.getUser();
            OIDCStateInfo stateInfoOIDC = new OIDCStateInfo();
            stateInfoOIDC.setAuthenticationInfo(authenticationInfo);
            context.setStateInfo(stateInfoOIDC);
            AuthenticatedUser authenticatedUser =
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(user.getSubject());

            Map<ClaimMapping, String> claims = new HashMap<>();
            Map<String, Object> attributes = user.getAttributes();
            String attributeSeparator = getMultiAttributeSeparator(context, user.getSubject());
            for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                buildClaimMappings(claims, entry, attributeSeparator);
            }
            authenticatedUser.setUserAttributes(claims);
            context.setSubject(authenticatedUser);

        } catch (IOException | ApplicationAuthenticatorException | SSOAgentClientException | SSOAgentServerException e) {
            log.error("Exception while processing the authentication response.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    protected void initiateLogoutRequest(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) throws LogoutFailedException {

        if (isLogoutEnabled(context)) {
            try {
                OIDCAgentConfig config = new AuthenticationContextBasedOIDCConfigProvider(context).getOidcAgentConfig();
                OIDCManager oidcManager = new OIDCManagerImpl(config);
                String state = getStateParameter(context, context.getAuthenticatorProperties());
                AuthenticationInfo authenticationInfo = getAuthenticationInfo(context);

                oidcManager.logout(authenticationInfo, response, state);
            } catch (SSOAgentException | ApplicationAuthenticatorException | IOException e) {
                log.error("Error occurred while initiating the logout request to IdP.");
                throw new LogoutFailedException(e.getMessage(), e);
            }
        } else {
            super.initiateLogoutRequest(request, response, context);
        }
    }

    private AuthenticationInfo getAuthenticationInfo(AuthenticationContext context) {

        if (context.getStateInfo() instanceof OIDCStateInfo) {
            return ((OIDCStateInfo) context.getStateInfo()).getAuthenticationInfo();
        }
        return null;
    }

    private boolean isLogoutEnabled(AuthenticationContext context) {

        String logoutUrl = getLogoutUrl(context.getAuthenticatorProperties());
        return StringUtils.isNotBlank(logoutUrl);
    }

    private String getIdTokenHint(AuthenticationContext context) {

        if (context.getStateInfo() instanceof OIDCStateInfo) {
            return ((OIDCStateInfo) context.getStateInfo()).getIdTokenHint();
        }
        return null;
    }

    private Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(OIDCAuthenticatorConstants.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parseJSONObject(new String(decoded)).entrySet();
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }

    private String getMultiAttributeSeparator(AuthenticationContext context, String authenticatedUserId)
            throws AuthenticationFailedException {

        String attributeSeparator = null;
        try {

            String tenantDomain = context.getTenantDomain();

            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            int tenantId = OpenIDConnectAuthenticatorDataHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            UserRealm userRealm = OpenIDConnectAuthenticatorDataHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId);

            if (userRealm != null) {
                UserStoreManager userStore = (UserStoreManager) userRealm.getUserStoreManager();
                attributeSeparator = userStore.getRealmConfiguration()
                        .getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
                if (log.isDebugEnabled()) {
                    log.debug("For the claim mapping: " + attributeSeparator
                            + " is used as the attributeSeparator in tenant: " + tenantDomain);
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while retrieving multi attribute separator",
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId), e);
        }
        return attributeSeparator;
    }

    private String getAuthenticatedUserId(AuthenticationContext context, OAuthClientResponse oAuthResponse,
                                          Map<String, Object> idTokenClaims) throws AuthenticationFailedException {

        String authenticatedUserId;
        if (isUserIdFoundAmongClaims(context)) {
            authenticatedUserId = getSubjectFromUserIDClaimURI(context, idTokenClaims);
            if (StringUtils.isNotBlank(authenticatedUserId)) {
                if (log.isDebugEnabled()) {
                    log.debug("Authenticated user id: " + authenticatedUserId + " was found among id_token claims.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Subject claim could not be found amongst id_token claims. Defaulting to the 'sub' "
                            + "attribute in id_token as authenticated user id.");
                }
                // Default to userId sent as the 'sub' claim.
                authenticatedUserId = getAuthenticateUser(context, idTokenClaims, oAuthResponse);
            }
        } else {
            authenticatedUserId = getAuthenticateUser(context, idTokenClaims, oAuthResponse);
            if (log.isDebugEnabled()) {
                log.debug("Authenticated user id: " + authenticatedUserId + " retrieved from the 'sub' claim.");
            }
        }

        if (authenticatedUserId == null) {
            throw new AuthenticationFailedException(
                    "Cannot find the userId from the id_token sent by the federated IDP.");
        }
        return authenticatedUserId;
    }

    private boolean isUserIdFoundAmongClaims(AuthenticationContext context) {

        return Boolean.parseBoolean(context.getAuthenticatorProperties()
                .get(IdentityApplicationConstants.Authenticator.OIDC.IS_USER_ID_IN_CLAIMS));
    }

    protected void buildClaimMappings(Map<ClaimMapping, String> claims, Map.Entry<String, Object> entry,
                                      String separator) {

        StringBuilder claimValue = null;
        if (StringUtils.isBlank(separator)) {
            separator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
        }
        if (entry.getValue() instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) entry.getValue();
            if (jsonArray != null && !jsonArray.isEmpty()) {
                Iterator attributeIterator = jsonArray.iterator();
                while (attributeIterator.hasNext()) {
                    if (claimValue == null) {
                        claimValue = new StringBuilder(attributeIterator.next().toString());
                    } else {
                        claimValue.append(separator).append(attributeIterator.next().toString());
                    }
                }
            }
        } else {
            claimValue =
                    entry.getValue() != null ? new StringBuilder(entry.getValue().toString()) : new StringBuilder();
        }
        claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
                claimValue != null ? claimValue.toString() : StringUtils.EMPTY);
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            log.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : " + claimValue);
        }

    }

    protected OAuthClientRequest getAccessTokenRequest(AuthenticationContext context, OAuthAuthzResponse
            authzResponse) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndPoint = getTokenEndpoint(authenticatorProperties);

        String callbackUrl = getCallbackUrlFromInitialRequestParamMap(context);
        if (StringUtils.isBlank(callbackUrl)) {
            callbackUrl = getCallbackUrl(authenticatorProperties);
        }

        boolean isHTTPBasicAuth = Boolean.parseBoolean(authenticatorProperties.get(OIDCAuthenticatorConstants
                .IS_BASIC_AUTH_ENABLED));

        OAuthClientRequest accessTokenRequest;
        try {
            if (isHTTPBasicAuth) {

                if (log.isDebugEnabled()) {
                    log.debug("Authenticating to token endpoint: " + tokenEndPoint + " with HTTP basic " +
                            "authentication scheme.");
                }

                accessTokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).setGrantType(GrantType
                        .AUTHORIZATION_CODE).setRedirectURI(callbackUrl).setCode(authzResponse.getCode())
                        .buildBodyMessage();
                String base64EncodedCredential = new String(Base64.encodeBase64((clientId + ":" +
                        clientSecret).getBytes()));
                accessTokenRequest.addHeader(OAuth.HeaderType.AUTHORIZATION, "Basic " + base64EncodedCredential);
            } else {

                if (log.isDebugEnabled()) {
                    log.debug("Authenticating to token endpoint: " + tokenEndPoint + " including client credentials "
                            + "in request body.");
                }

                accessTokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).setGrantType(GrantType
                        .AUTHORIZATION_CODE).setClientId(clientId).setClientSecret(clientSecret).setRedirectURI
                        (callbackUrl).setCode(authzResponse.getCode()).buildBodyMessage();
            }
            // set 'Origin' header to access token request.
            if (accessTokenRequest != null) {
                // fetch the 'Hostname' configured in carbon.xml
                String serverURL = IdentityUtil.getServerURL("", false, false);
                accessTokenRequest.addHeader(OIDCAuthenticatorConstants.HTTP_ORIGIN_HEADER, serverURL);
            }
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while building access token request for token endpoint: " + tokenEndPoint, e);
            }

            throw new AuthenticationFailedException(e.getMessage(), e);
        }

        return accessTokenRequest;
    }

    protected OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception while requesting access token", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return oAuthResponse;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside OpenIDConnectAuthenticator.getContextIdentifier()");
        }
        String state = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    private String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 1) {
                return stateElements[1];
            }
        }
        return null;
    }

    @Override
    public String getFriendlyName() {

        return "openidconnect";
    }

    @Override
    public String getName() {

        return OIDCAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getClaimDialectURI() {

        return "http://wso2.org/oidc/claim";
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        Property clientId = new Property();
        clientId.setName(IdentityApplicationConstants.Authenticator.OIDC.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter OAuth2/OpenID Connect client identifier value");
        clientId.setType("string");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(IdentityApplicationConstants.Authenticator.OIDC.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setDescription("Enter OAuth2/OpenID Connect client secret value");
        clientSecret.setType("string");
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property authzEpUrl = new Property();
        authzEpUrl.setName(IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_AUTHZ_URL);
        authzEpUrl.setDisplayName("Authorization Endpoint URL");
        authzEpUrl.setRequired(true);
        authzEpUrl.setDescription("Enter OAuth2/OpenID Connect authorization endpoint URL value");
        authzEpUrl.setType("string");
        authzEpUrl.setDisplayOrder(3);
        configProperties.add(authzEpUrl);

        Property tokenEpUrl = new Property();
        tokenEpUrl.setName(IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
        tokenEpUrl.setDisplayName("Token Endpoint URL");
        tokenEpUrl.setRequired(true);
        tokenEpUrl.setDescription("Enter OAuth2/OpenID Connect token endpoint URL value");
        tokenEpUrl.setType("string");
        tokenEpUrl.setDisplayOrder(4);
        configProperties.add(tokenEpUrl);

        Property callBackUrl = new Property();
        callBackUrl.setName(IdentityApplicationConstants.Authenticator.OIDC.CALLBACK_URL);
        callBackUrl.setDisplayName("Callback Url");
        callBackUrl.setRequired(false);
        callBackUrl.setDescription("Enter value corresponding to callback url");
        callBackUrl.setType("string");
        callBackUrl.setDisplayOrder(5);
        configProperties.add(callBackUrl);

        Property userInfoUrl = new Property();
        userInfoUrl.setName(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
        userInfoUrl.setDisplayName("Userinfo Endpoint URL");
        userInfoUrl.setRequired(false);
        userInfoUrl.setDescription("Enter value corresponding to userinfo endpoint url");
        userInfoUrl.setType("string");
        userInfoUrl.setDisplayOrder(6);
        configProperties.add(userInfoUrl);

        Property userIdLocation = new Property();
        userIdLocation.setName(IdentityApplicationConstants.Authenticator.OIDC.IS_USER_ID_IN_CLAIMS);
        userIdLocation.setDisplayName("OpenID Connect User ID Location");
        userIdLocation.setRequired(false);
        userIdLocation.setDescription("Specifies the location to find the user identifier in the ID token assertion");
        userIdLocation.setType("boolean");
        userIdLocation.setDisplayOrder(7);
        configProperties.add(userIdLocation);

        Property additionalParams = new Property();
        additionalParams.setName("commonAuthQueryParams");
        additionalParams.setDisplayName("Additional Query Parameters");
        additionalParams.setRequired(false);
        additionalParams.setDescription("Additional query parameters. e.g: paramName1=value1");
        additionalParams.setType("string");
        additionalParams.setDisplayOrder(8);
        configProperties.add(additionalParams);

        Property enableBasicAuth = new Property();
        enableBasicAuth.setName(IdentityApplicationConstants.Authenticator.OIDC.IS_BASIC_AUTH_ENABLED);
        enableBasicAuth.setDisplayName("Enable HTTP basic auth for client authentication");
        enableBasicAuth.setRequired(false);
        enableBasicAuth.setDescription(
                "Specifies that HTTP basic authentication should be used for client authentication, else client credentials will be included in the request body");
        enableBasicAuth.setType("boolean");
        enableBasicAuth.setDisplayOrder(9);
        configProperties.add(enableBasicAuth);

        return configProperties;
    }

    /**
     * @subject
     */
    protected String getSubjectFromUserIDClaimURI(AuthenticationContext context) {

        String subject = null;
        try {
            subject = FrameworkUtils.getFederatedSubjectFromClaims(context, getClaimDialectURI());
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Couldn't find the subject claim from claim mappings ", e);
            }
        }
        return subject;
    }

    protected String getSubjectFromUserIDClaimURI(AuthenticationContext context, Map<String, Object> idTokenClaims)
            throws AuthenticationFailedException {

        boolean useLocalClaimDialect = context.getExternalIdP().useDefaultLocalIdpDialect();
        String userIdClaimUri = context.getExternalIdP().getUserIdClaimUri();
        String spTenantDomain = context.getTenantDomain();

        try {
            String userIdClaimUriInOIDCDialect = null;
            if (useLocalClaimDialect) {
                if (StringUtils.isNotBlank(userIdClaimUri)) {
                    // User ID is defined in local claim dialect at the IDP. Find the corresponding OIDC claim and retrieve
                    // from idTokenClaims.
                    userIdClaimUriInOIDCDialect = getUserIdClaimUriInOIDCDialect(userIdClaimUri, spTenantDomain);
                } else {
                    if (log.isDebugEnabled()) {
                        String idpName = context.getExternalIdP().getIdPName();
                        log.debug("User ID Claim URI is not configured for IDP: " + idpName + ". " +
                                "Cannot retrieve subject using user id claim URI.");
                    }
                }
            } else {
                ClaimMapping[] claimMappings = context.getExternalIdP().getClaimMappings();
                // Try to find the userIdClaimUri within the claimMappings.
                if (!ArrayUtils.isEmpty(claimMappings)) {
                    for (ClaimMapping claimMapping : claimMappings) {
                        if (log.isDebugEnabled()) {
                            log.debug("Evaluating " + claimMapping.getRemoteClaim().getClaimUri() + " against " +
                                    userIdClaimUri);
                        }
                        if (StringUtils.equals(claimMapping.getRemoteClaim().getClaimUri(), userIdClaimUri)) {
                            // Get the subject claim in OIDC dialect.
                            String userIdClaimUriInLocalDialect = claimMapping.getLocalClaim().getClaimUri();
                            userIdClaimUriInOIDCDialect =
                                    getUserIdClaimUriInOIDCDialect(userIdClaimUriInLocalDialect, spTenantDomain);
                            break;
                        }
                    }
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("using userIdClaimUriInOIDCDialect to get subject from idTokenClaims: " +
                        userIdClaimUriInOIDCDialect);
            }
            Object subject = idTokenClaims.get(userIdClaimUriInOIDCDialect);
            if (subject instanceof String) {
                return (String) subject;
            } else if (subject != null) {
                log.warn("Unable to map subject claim (non-String type): " + subject);
            }
        } catch (ClaimMetadataException ex) {
            throw new AuthenticationFailedException(
                    "Error while executing claim transformation for IDP: " + context.getExternalIdP().getIdPName(), ex);
        }
        if (log.isDebugEnabled()) {
            log.debug("Couldn't find the subject claim among id_token claims for IDP: " + context.getExternalIdP()
                    .getIdPName());
        }
        return null;
    }

    private String getUserIdClaimUriInOIDCDialect(String userIdClaimInLocalDialect, String spTenantDomain)
            throws ClaimMetadataException {

        List<ExternalClaim> externalClaims = OpenIDConnectAuthenticatorDataHolder.getInstance()
                .getClaimMetadataManagementService().getExternalClaims(OIDC_DIALECT, spTenantDomain);
        String userIdClaimUri = null;
        ExternalClaim oidcUserIdClaim = null;

        for (ExternalClaim externalClaim : externalClaims) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Evaluating " + userIdClaimInLocalDialect + " against " + externalClaim.getMappedLocalClaim());
            }
            if (userIdClaimInLocalDialect.equals(externalClaim.getMappedLocalClaim())) {
                oidcUserIdClaim = externalClaim;
            }
        }

        if (oidcUserIdClaim != null) {
            userIdClaimUri = oidcUserIdClaim.getClaimURI();
        }

        return userIdClaimUri;
    }

    /**
     * Request user claims from user info endpoint.
     *
     * @param url         User info endpoint.
     * @param accessToken Access token.
     * @return Response string.
     * @throws IOException
     */
    protected String sendRequest(String url, String accessToken) throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Claim URL: " + url);
        }

        if (url == null) {
            return StringUtils.EMPTY;
        }

        StringBuilder builder = new StringBuilder();
        BufferedReader reader = null;

        try {
            URL obj = new URL(url);
            HttpURLConnection urlConnection = (HttpURLConnection) obj.openConnection();
            urlConnection.setRequestMethod("GET");
            urlConnection.setRequestProperty("Authorization", "Bearer " + accessToken);
            reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String inputLine = reader.readLine();

            while (inputLine != null) {
                builder.append(inputLine).append("\n");
                inputLine = reader.readLine();
            }
        } finally {
            if (reader != null) {
                reader.close();
            }
        }

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            log.debug("response: " + builder.toString());
        }
        return builder.toString();
    }

    private String interpretQueryString(String queryString, Map<String, String[]> parameters) {

        if (StringUtils.isBlank(queryString)) {
            return null;
        }
        Matcher matcher = pattern.matcher(queryString);
        while (matcher.find()) {
            String name = matcher.group(1);
            String[] values = parameters.get(name);
            String value = "";
            if (values != null && values.length > 0) {
                value = values[0];
            }
            try {
                value = URLEncoder.encode(value, StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException e) {
                log.error("Error while encoding the query param: " + name + " with value: " + value, e);
            }
            if (log.isDebugEnabled()) {
                log.debug("InterpretQueryString name: " + name + ", value: " + value);
            }
            queryString = queryString.replaceAll("\\$\\{" + name + "}", Matcher.quoteReplacement(value));
        }
        if (log.isDebugEnabled()) {
            log.debug("Output QueryString: " + queryString);
        }
        return queryString;
    }

    private String getCallbackUrlFromInitialRequestParamMap(AuthenticationContext context) {

        // 'oidc:param.map' is populated from the authorization request query string and being set in the
        // AuthenticationContext as a key value pair map. Therefore, it is always ensured that this map is available
        // and in of type Map<String, String>
        @SuppressWarnings({"unchecked"}) Map<String, String> paramValueMap = (Map<String, String>) context
                .getProperty(OIDCAuthenticatorConstants.OIDC_QUERY_PARAM_MAP_PROPERTY_KEY);

        if (MapUtils.isNotEmpty(paramValueMap) && paramValueMap.containsKey(OIDCAuthenticatorConstants.REDIRECT_URI)) {
            return paramValueMap.get(OIDCAuthenticatorConstants.REDIRECT_URI);
        }

        return null;
    }
}

