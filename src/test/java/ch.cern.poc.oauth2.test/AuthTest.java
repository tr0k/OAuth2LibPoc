package ch.cern.poc.oauth2.test;

import ch.cern.poc.oauth2.Common;
import junit.framework.Assert;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.FileAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.testng.annotations.Test;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.assertNotNull;

/**
 * Created by tr0k on 2016-07-28.
 */
public class AuthTest extends Arquillian{

    @ArquillianResource
    private URL url;
    private Client client = JerseyClientBuilder.newClient();

    @Deployment(testable=false)
    public static WebArchive createDeployment() {
        return ShrinkWrap.create(WebArchive.class)
                .addPackages(true, "ch.cern.poc.oauth2")
                .addAsWebInfResource(new FileAsset(new File("src/main/webapp/WEB-INF/beans.xml")), "beans.xml")
                .addAsWebInfResource(new FileAsset(new File("src/main/webapp/WEB-INF/web.xml")), "web.xml")
                .addAsLibraries(Maven.resolver().loadPomFromFile("pom.xml")
                        .importRuntimeDependencies().resolve().withTransitivity().asFile());
    }

    @Test
    public void authorizationRequest() {
        try {
            Response response = makeAuthCodeRequest();
            Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

            String authCode = getAuthCode(response);
            Assert.assertNotNull(authCode);
        } catch (OAuthSystemException | URISyntaxException | JSONException ex) {
            Logger.getLogger(AuthTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void authCodeTokenRequest() throws OAuthSystemException {
        try {
            Response response = makeAuthCodeRequest();
            Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

            String authCode = getAuthCode(response);
            Assert.assertNotNull(authCode);
            OAuthAccessTokenResponse oauthResponse = makeTokenRequestWithAuthCode(authCode);
            assertNotNull(oauthResponse.getAccessToken());
            assertNotNull(oauthResponse.getExpiresIn());
        } catch (OAuthSystemException | URISyntaxException | JSONException | OAuthProblemException ex) {
            Logger.getLogger(AuthTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void directTokenRequest() {
        try {
            OAuthClientRequest request = OAuthClientRequest
                    .tokenLocation(url.toString() + "api/token")
                    .setGrantType(GrantType.PASSWORD)
                    .setClientId(Common.CLIENT_ID)
                    .setClientSecret(Common.CLIENT_SECRET)
                    .setUsername(Common.USERNAME)
                    .setPassword(Common.PASSWORD)
                    .buildBodyMessage();

            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthAccessTokenResponse oauthResponse = oAuthClient.accessToken(request);
            assertNotNull(oauthResponse.getAccessToken());
            assertNotNull(oauthResponse.getExpiresIn());
        } catch (OAuthSystemException | OAuthProblemException ex ) {
            Logger.getLogger(AuthTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void endToEndWithAuthCode() {
        try {
            Response response = makeAuthCodeRequest();
            Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

            String authCode = getAuthCode(response);
            Assert.assertNotNull(authCode);

            OAuthAccessTokenResponse oauthResponse = makeTokenRequestWithAuthCode(authCode);
            String accessToken = oauthResponse.getAccessToken();

            URL restUrl = new URL(url.toString() + "api/resource");
            WebTarget target = client.target(restUrl.toURI());
            String entity = target.request(MediaType.TEXT_HTML)
                    .header(Common.HEADER_AUTHORIZATION, "Bearer " + accessToken)
                    .get(String.class);
            System.out.println("Response = " + entity);
        } catch (MalformedURLException | URISyntaxException | OAuthProblemException | OAuthSystemException | JSONException ex) {
            Logger.getLogger(AuthTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private Response makeAuthCodeRequest() throws OAuthSystemException, URISyntaxException {
        OAuthClientRequest request = OAuthClientRequest
                .authorizationLocation(url.toString() + "api/authz")
                .setClientId(Common.CLIENT_ID)
                .setRedirectURI(url.toString() + "api/redirect")
                .setResponseType(ResponseType.CODE.toString())
                .setState("state")
                .buildQueryMessage();
        WebTarget target = client.target(new URI(request.getLocationUri()));
        return target.request(MediaType.TEXT_HTML).get();
    }

    private String getAuthCode(Response response) throws JSONException {
        JSONObject obj = new JSONObject(response.readEntity(String.class));
        JSONObject qp = obj.getJSONObject("queryParameters");
        String authCode = null;
        if (qp != null) {
            authCode = qp.getString("code");
        }

        return authCode;
    }

    private OAuthAccessTokenResponse makeTokenRequestWithAuthCode(String authCode) throws OAuthProblemException, OAuthSystemException {
        OAuthClientRequest request = OAuthClientRequest
                .tokenLocation(url.toString() + "api/token")
                .setClientId(Common.CLIENT_ID)
                .setClientSecret(Common.CLIENT_SECRET)
                .setGrantType(GrantType.AUTHORIZATION_CODE)
                .setCode(authCode)
                .setRedirectURI(url.toString() + "api/redirect")
                .buildBodyMessage();
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        return oAuthClient.accessToken(request);
    }
}
