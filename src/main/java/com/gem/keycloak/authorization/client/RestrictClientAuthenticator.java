package com.gem.keycloak.authorization.client;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientValidator;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.representations.AccessToken;

import java.util.Set;

final class RestrictClientAuthenticator implements ClientAuthenticator {
    private static final Logger LOG = Logger.getLogger(RestrictClientAuthenticator.class);;

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        JWTClientValidator validator = new JWTClientValidator(context);
        String clientAssertion = validator.getClientAssertion();
        final ClientModel client = validator.getClient();

        final String accessRolePrefix = "_access_role";
        final String accessRoleName = client.getName().concat(accessRolePrefix);
        LOG.warn("Restrict client :".concat(client.getName()));

        AccessToken accessToken = context.getSession().tokens().decodeClientJWT(clientAssertion, client, AccessToken.class);

        Set<String> accessRole = accessToken.getResourceAccess().get(client.getName()).getRoles();


        if (accessRole.contains(accessRoleName)) {
            context.success();
        } else {
            context.getEvent()
                .realm(context.getRealm())
                .client(client)
                .error(Errors.ACCESS_DENIED);
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    }

    @Override
    public void close() {

    }

//    private static final Logger LOG = Logger.getLogger(RestrictClientAuthAuthenticator.class);
//
//    RestrictClientAuthAuthenticator() {
//    }
//
//    @Override
//    public void authenticate(AuthenticationFlowContext context) {
//        final ClientModel client = context.getSession().getContext().getClient();
//
////        final RestrictClientAuthConfig config = new RestrictClientAuthConfig(context.getAuthenticatorConfig());
////
////        final AccessProvider access = getAccessProvider(context, config);
////
////        if (!access.isRestricted(client)) {
////            context.success();
////            return;
////        }
//        final String accessRolePrefix = "_access_role";
//        final String accessRoleName = client.getName().concat(accessRolePrefix);
//        LOG.warn("Restrict client :".concat(client.getName()));
//
//        final UserModel user = context.getUser();
//
//        List<String> listUserRoleName = user.getRoleMappingsStream().map(RoleModel::getName).toList();
//
//        if (listUserRoleName.contains(accessRoleName)) {
//            context.success();
//        } else {
//            context.getEvent()
//                .realm(context.getRealm())
//                .client(client)
//                .user(context.getUser())
//                .error(Errors.ACCESS_DENIED);
//            context.failure(AuthenticationFlowError.ACCESS_DENIED);
//        }
//
////        if (access.isPermitted(client, user)) {
////            context.success();
////        } else {
////            context.getEvent()
////                .realm(context.getRealm())
////                .client(client)
////                .user(context.getUser())
////                .error(Errors.ACCESS_DENIED);
////            context.failure(AuthenticationFlowError.ACCESS_DENIED, errorResponse(context, config));
////        }
//    }
////
////    private AccessProvider getAccessProvider(AuthenticationFlowContext context, RestrictClientAuthConfig config) {
////        final String accessProviderId = config.getAccessProviderId();
////
////        if (accessProviderId != null) {
////            AccessProvider accessProvider = context.getSession().getProvider(AccessProvider.class, accessProviderId);
////            if (accessProvider == null) {
////                LOG.warnf(
////                    "Configured access provider '%s' in authenticator config '%s' does not exist.",
////                    accessProviderId, config.getAuthenticatorConfigAlias());
////            } else {
////                LOG.tracef(
////                    "Using access provider '%s' in authenticator config '%s'.",
////                    accessProviderId, config.getAuthenticatorConfigAlias());
////                return accessProvider;
////            }
////        }
////
////        final AccessProvider defaultProvider = context.getSession().getProvider(AccessProvider.class);
////        if (defaultProvider != null) {
////            LOG.debugf(
////                "No access provider is configured in authenticator config '%s'. Using server-wide default provider '%s'",
////                config.getAuthenticatorConfigAlias(), defaultProvider);
////            return defaultProvider;
////        }
////
////        LOG.infof(
////            "Neither an access provider is configured in authenticator config '%s' nor has a server-wide default provider been set. Using '%s' as a fallback.",
////            config.getAuthenticatorConfigAlias(), ClientRoleBasedAccessProviderFactory.PROVIDER_ID);
////        return context.getSession().getProvider(AccessProvider.class, ClientRoleBasedAccessProviderFactory.PROVIDER_ID);
////    }
//
//    private Response errorResponse(AuthenticationFlowContext context, RestrictClientAuthConfig config) {
//        Response response;
//        if (MediaTypeMatcher.isHtmlRequest(context.getHttpRequest().getHttpHeaders())) {
//            response = htmlErrorResponse(context, config);
//        } else {
//            response = oAuth2ErrorResponse();
//        }
//        return response;
//    }
//
//    private Response htmlErrorResponse(AuthenticationFlowContext context, RestrictClientAuthConfig config) {
//        AuthenticationSessionModel authSession = context.getAuthenticationSession();
//        return context.form()
//            .setError(config.getErrorMessage(), authSession.getAuthenticatedUser().getUsername(),
//                authSession.getClient().getClientId())
//            .createErrorPage(Response.Status.FORBIDDEN);
//    }
//
//    private static Response oAuth2ErrorResponse() {
//        return Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
//            .entity(new OAuth2ErrorRepresentation(Messages.ACCESS_DENIED, "Access to client is denied."))
//            .type(MediaType.APPLICATION_JSON_TYPE)
//            .build();
//    }
//
//    @Override
//    public void action(AuthenticationFlowContext context) {
//        LOG.warn("Action called!");
//        context.failure(AuthenticationFlowError.ACCESS_DENIED);
//    }
//
//    @Override
//    public boolean requiresUser() {
//        return true;
//    }
//
//    @Override
//    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
//        return true;
//    }
//
//    @Override
//    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
//    }
//
//    @Override
//    public void close() {
//    }

}
