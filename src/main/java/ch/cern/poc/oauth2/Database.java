package ch.cern.poc.oauth2;

import javax.enterprise.context.ApplicationScoped;
import java.util.HashSet;
import java.util.Set;

/**
 * Fake, basic databaase to store authentication codes and tokens for valid users.
 * Created by tr0k on 2016-07-28.
 */
@ApplicationScoped
public class Database {
    private Set<String> authCodes = new HashSet<>();
    private Set<String> tokens = new HashSet<>();

    public void addAuthCode(String authCode) {
        authCodes.add(authCode);
    }

    public boolean isValidAuthCode(String authCode) {
        return authCodes.contains(authCode);
    }

    public void addToken(String token) {
        tokens.add(token);
    }

    public boolean isValidToken(String token) {
        return tokens.contains(token);
    }

}
