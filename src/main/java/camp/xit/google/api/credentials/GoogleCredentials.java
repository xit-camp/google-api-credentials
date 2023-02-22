package camp.xit.google.api.credentials;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class GoogleCredentials {

    private static final Logger LOG = LoggerFactory.getLogger(GoogleCredentials.class);
    private static final int TOKEN_EXPIRATION = 3600;
    private static final JsonMapper JSON_MAPPER = getJsonMapper();

    private final ExpirationSupplier<ClientAccessToken> tokenCache;
    private final JsonMapper jsonMapper;
    private final HttpClient httpClient;
    private final ServiceAccount serviceAccount;
    private final String scopes;

    public GoogleCredentials(Path serviceAccountFile, String... scopes) {
        this(serviceAccountFile.toFile(), scopes);
    }

    public GoogleCredentials(File serviceAccountFile, String... scopes) {
        this(readServiceAccount(serviceAccountFile), scopes);
    }

    public GoogleCredentials(InputStream serviceAccount, String... scopes) {
        this(readServiceAccount(serviceAccount), scopes);
    }

    public GoogleCredentials(ServiceAccount serviceAccount, String... scopes) {
        this.jsonMapper = getJsonMapper();
        this.httpClient = HttpClient.newHttpClient();
        this.serviceAccount = serviceAccount;
        this.tokenCache = new ExpirationSupplier<>(this::readToken, TOKEN_EXPIRATION - 3, TimeUnit.SECONDS);
        this.scopes = String.join(" ", Arrays.asList(scopes));
    }

    public ClientAccessToken getAccessToken() {
        return tokenCache.get();
    }

    private static JsonMapper getJsonMapper() {
        JsonMapper mapper = new JsonMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES);
        return mapper;
    }

    private static ServiceAccount readServiceAccount(File serviceAccountFile) {
        try {
            return JSON_MAPPER.readValue(serviceAccountFile, ServiceAccount.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read service account file", e);
        }
    }

    private static ServiceAccount readServiceAccount(InputStream serviceAcount) {
        try {
            return JSON_MAPPER.readValue(serviceAcount, ServiceAccount.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read service account file", e);
        }
    }

    private ClientAccessToken readToken(ClientAccessToken previousValue, long lastModification) {
        LOG.info("Refreshing access token");

        Instant now = Instant.now();
        Algorithm algorithm = Algorithm.RSA256(null, serviceAccount.getPrivateKey());
        String encodedToken = JWT.create()
                .withIssuer(serviceAccount.getClientEmail())
                .withAudience(serviceAccount.getTokenUri())
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(TOKEN_EXPIRATION)))
                .withClaim("scope", scopes)
                .sign(algorithm);

        String type = URLEncoder.encode(OAuthConstants.JWT_BEARER_GRANT, Charset.defaultCharset());
        String assertion = URLEncoder.encode(encodedToken, Charset.defaultCharset());
        String query = "grant_type=" + type + "&assertion=" + assertion;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serviceAccount.getTokenUri()))
                .POST(HttpRequest.BodyPublishers.ofString(query))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .build();

        try {
            HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() == 200 || response.statusCode() == 201) {
                try (InputStream in = response.body()) {
                    return jsonMapper.readValue(in, ClientAccessToken.class);
                }
            } else {
                String content = consumeContent(response.body());
                throw new RuntimeException(content);
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Cannot read access token", e);
        }
    }

    private String consumeContent(InputStream inputStream) throws IOException {
        try (inputStream) {
            return new BufferedReader(
                    new InputStreamReader(inputStream, StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));
        }
    }
}
