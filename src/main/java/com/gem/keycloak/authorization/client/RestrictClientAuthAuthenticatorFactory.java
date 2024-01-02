package com.gem.keycloak.authorization.client;

import lombok.extern.slf4j.Slf4j;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientValidator;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

@Slf4j
public final class RestrictClientAuthAuthenticatorFactory extends AbstractClientAuthenticator {

    private static final Logger LOG = Logger.getLogger(RestrictClientAuthAuthenticatorFactory.class);

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]{REQUIRED, DISABLED};
    public static final String PROVIDER_ID = "restrict-client-authenticator";
    private static final ClientAuthenticator CLIENT_AUTHENTICATOR = new RestrictClientAuthAuthenticator();

    static final String ALLOWED_IP_ADDRESS_CONFIG = "allowed_group_by_client_access_role";

    @Override
    public String getId() {
        return null;
    }

    @Override
    public String getDisplayType() {
        return "Restrict Client Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        ProviderConfigProperty name = new ProviderConfigProperty();

        name.setType(STRING_TYPE);
        name.setName(ALLOWED_IP_ADDRESS_CONFIG);
        name.setLabel("IP Address from which sign ins are allowed");
        name.setHelpText("Only accepts IP addresses, no CIDR nor masks nor ranges supported");

        return Collections.singletonList(name);
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        Map<String, Object> props = new HashMap<>();
        props.put("client-keystore-file", "REPLACE WITH THE LOCATION OF YOUR KEYSTORE FILE");
        props.put("client-keystore-type", "jks");
        props.put("client-keystore-password", "REPLACE WITH THE KEYSTORE PASSWORD");
        props.put("client-key-password", "REPLACE WITH THE KEY PASSWORD IN KEYSTORE");
        props.put("client-key-alias", client.getClientId());
        props.put("token-timeout", 10);
        String algorithm = client.getAttribute(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG);
        if (algorithm != null) {
            props.put("algorithm", algorithm);
        }

        Map<String, Object> config = new HashMap<>();
        config.put("jwt", props);
        return config;
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        if (loginProtocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            Set<String> results = new HashSet<>();
            results.add(OIDCLoginProtocol.PRIVATE_KEY_JWT);
            return results;
        } else {
            return Collections.emptySet();
        }
    }

    @Override
    public boolean supportsSecret() {
        return super.supportsSecret();
    }

    @Override
    public String getHelpText() {
        return "Restricts user authentication on clients based on an access provider";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        JWTClientValidator validator = new JWTClientValidator(context);
        String clientAssertion = validator.getClientAssertion();
        final ClientModel client = validator.getClient();

        final String accessRolePrefix = "_access_role";
        final String accessRoleName = client.getName().concat(accessRolePrefix);
        log.warn("Restrict client :".concat(client.getName()));
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
}
