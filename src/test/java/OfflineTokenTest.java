import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.keycloak.client.KeycloakTestClient;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.*;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@QuarkusTest
class OfflineTokenTest {
    @Inject
    Keycloak keycloak;

    @Inject
    AuthzClient authzClient;

    @Test
    void testPermissions() {
        var client = new KeycloakTestClient();
        var realmResource = keycloak.realm("test-tenant");
        var clientResourceId =
                realmResource.clients().findByClientId("authz-client").getFirst().getId();
        var authorizationResource = realmResource.clients().get(clientResourceId).authorization();


        createUser("testuser", realmResource.users());
        addPolicyForUser(authorizationResource, "testuser-policy", "testuser");
        addResource(authorizationResource, "testuser-resource");
        addPermission(authorizationResource, "testuser-permission", Set.of("testuser-resource"), Set.of("testuser-policy"));

        var token = client.getAccessToken("testuser", "testuser", "api-client", "secret", List.of("offline_access"));

        System.out.println("Token: " + token);
        var request = new AuthorizationRequest();
        var response = authzClient.authorization(token).authorize(request);
        String rpt = response.getToken();
        System.out.println("RPT: " + rpt);
        var introspection = authzClient.protection().introspectRequestingPartyToken(rpt);

        introspection.getPermissions().forEach(System.out::println);

        assertThat(introspection.getActive()).isTrue();
        assertThat(introspection.getPermissions()).isNotEmpty()
                .singleElement()
                .satisfies(permission -> {
                    assertThat(permission.getResourceName()).isEqualTo("testuser-resource");
                });

    }

    private String createUser(String username, UsersResource usersResource) {
        UserRepresentation newUser = new UserRepresentation();
        newUser.setUsername(username);
        newUser.setEnabled(true);
        CredentialRepresentation passwordCredential = new CredentialRepresentation();
        passwordCredential.setType(CredentialRepresentation.PASSWORD);
        passwordCredential.setTemporary(false);
        passwordCredential.setValue(username);
        newUser.setCredentials(List.of(passwordCredential));
        Response response = usersResource.create(newUser);
        return CreatedResponseUtil.getCreatedId(response);
    }

    void addPolicyForUser(AuthorizationResource authorizationResource, String policyName, String username) {
        var policy = new UserPolicyRepresentation();
        policy.setName(policyName);
        policy.setLogic(Logic.POSITIVE);
        policy.setUsers(Set.of(username));
        authorizationResource.policies().user().create(policy);
    }

    void addResource(AuthorizationResource authorizationResource, String resourceName) {
        ResourceRepresentation resourceRepresentation = new ResourceRepresentation(resourceName);
        resourceRepresentation.setUris(Set.of("/uri1", "/uri2"));
        resourceRepresentation.setDisplayName(resourceName + "-Test");
        authorizationResource.resources().create(resourceRepresentation);
    }

    void addPermission(AuthorizationResource authorizationResource, String permissionName, Set<String> resources, Set<String> policyNames) {
        var permission = new ResourcePermissionRepresentation();
        permission.setName(permissionName);
        permission.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);
        permission.setResources(resources);
        permission.setLogic(Logic.POSITIVE);
        permission.setPolicies(policyNames);
        authorizationResource.permissions().resource().create(permission);
    }
}
