package ch.cern.poc.oauth2.endpoints;

import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriInfo;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Retrieve headers and parameters return in response from authorization server.
 * Created by tr0k on 2016-07-28.
 */
@Path("/redirect")
public class RedirectEndpoint {
    @Context
    HttpHeaders httpHeaders;
    @Context
    UriInfo uriInfo;

    /**
     * @return JSON with headers and parameters obtained from response from authorization server.
     */
    @GET
    public String redirect() {
        JSONObject object = new JSONObject();
        JSONObject headers = new JSONObject();
        JSONObject queryparams = new JSONObject();
        String json = "Error!";
        try {
            for (Map.Entry<String, List<String>> entry : httpHeaders.getRequestHeaders().entrySet()) {
                headers.put(entry.getKey(), entry.getValue().get(0));
            }
            object.put("headers", headers);
            for (Map.Entry<String, List<String>> entry : uriInfo.getQueryParameters().entrySet()) {
                queryparams.put(entry.getKey(), entry.getValue().get(0));
            }
            object.put("queryParameters", queryparams);
            json = object.toString(4);
        } catch (JSONException ex) {
            Logger.getLogger(RedirectEndpoint.class.getName()).log(Level.SEVERE, null, ex);
        }
        return json;
    }
}
