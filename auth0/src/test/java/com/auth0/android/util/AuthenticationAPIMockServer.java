package com.auth0.android.util;

import com.auth0.android.request.SSLTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

public class AuthenticationAPIMockServer {

    public static final String REFRESH_TOKEN = "REFRESH_TOKEN";
    public static final String ID_TOKEN = "ID_TOKEN";
    public static final String ACCESS_TOKEN = "ACCESS_TOKEN";
    private static final String BEARER = "BEARER";
    public static final String GENERIC_TOKEN = "GENERIC_TOKEN";
    private static final String NEW_ID_TOKEN = "NEW_ID_TOKEN";
    private static final String TOKEN_TYPE = "TOKEN_TYPE";
    private static final int EXPIRES_IN = 1234567890;

    private final MockWebServer server;

    public AuthenticationAPIMockServer() throws IOException {
        this.server = SSLTestUtils.INSTANCE.createMockWebServer();
        this.server.start();
    }

    public String getDomain() {
        return server.url("/").toString();
    }

    public void shutdown() throws IOException {
        this.server.shutdown();
    }

    public RecordedRequest takeRequest() throws InterruptedException {
        return server.takeRequest();
    }

    public AuthenticationAPIMockServer willReturnValidApplicationResponse() {
        return willReturnApplicationResponseWithBody("Auth0.setClient({\"id\":\"CLIENTID\",\"tenant\":\"overmind\",\"subscription\":\"free\",\"authorize\":\"https://samples.auth0.com/authorize\",\"callback\":\"http://localhost:3000/\",\"hasAllowedOrigins\":true,\"strategies\":[{\"name\":\"twitter\",\"connections\":[{\"name\":\"twitter\"}]}]});", 200);
    }

    public AuthenticationAPIMockServer willReturnSuccessfulChangePassword() {
        server.enqueue(responseWithJSON("NOT REALLY A JSON", 200));
        return this;
    }

    public AuthenticationAPIMockServer willReturnSuccessfulPasswordlessStart() {
        String json = "{\n" +
                "  \"phone+number\": \"+1098098098\"\n" +
                "}";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    public AuthenticationAPIMockServer willReturnNewIdToken() {
        String json = "{\n" +
                "  \"id_token\": \"" + NEW_ID_TOKEN + "\",\n" +
                "  \"expires_in\": " + EXPIRES_IN + ",\n" +
                "  \"token_type\": \"" + TOKEN_TYPE + "\"\n" +
                "}";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    public AuthenticationAPIMockServer willReturnSuccessfulSignUp() {
        String json = "{\n" +
                "    \"_id\": \"gjsmgdkjs72jljsf2dsdhh\", \n" +
                "    \"email\": \"support@auth0.com\", \n" +
                "    \"email_verified\": false, \n" +
                "    \"username\": \"support\"\n" +
                "}";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    public AuthenticationAPIMockServer willReturnSuccessfulEmptyBody() {
        server.enqueue(responseEmpty(200));
        return this;
    }

    public AuthenticationAPIMockServer willReturnSuccessfulLogin() {
        String json = "{\n" +
                "  \"refresh_token\": \"" + REFRESH_TOKEN + "\",\n" +
                "  \"id_token\": \"" + ID_TOKEN + "\",\n" +
                "  \"access_token\": \"" + ACCESS_TOKEN + "\",\n" +
                "  \"token_type\": \"" + BEARER + "\"\n" +
                "}";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    public AuthenticationAPIMockServer willReturnInvalidRequest() {
        String json = "{\n" +
                "  \"error\": \"invalid_request\",\n" +
                "  \"error_description\": \"a random error\"\n" +
                "}";
        server.enqueue(responseWithJSON(json, 400));
        return this;
    }

    public AuthenticationAPIMockServer willReturnEmptyJsonWebKeys() {
        String json = "{" +
                "\"keys\": []" +
                "}";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    public AuthenticationAPIMockServer willReturnValidJsonWebKeys() {
        try {
            byte[] encoded = Files.readAllBytes(Paths.get("src/test/resources/rsa_jwks.json"));
            String json = new String(encoded);
            server.enqueue(responseWithJSON(json, 200));
        } catch (Exception ignored) {
            System.out.println("File parsing error");
        }
        return this;
    }

    public AuthenticationAPIMockServer willReturnUserInfo() {
        String json = "{\n" +
                "  \"email\": \"p@p.xom\",\n" +
                "  \"email_verified\": false,\n" +
                "  \"picture\": \"https://secure.gravatar.com/avatar/cfacbe113a96fdfc85134534771d88b4?s=480&r=pg&d=https%3A%2F%2Fssl.gstatic.com%2Fs2%2Fprofiles%2Fimages%2Fsilhouette80.png\",\n" +
                "  \"user_id\": \"auth0|53b995f8bce68d9fc900099c\",\n" +
                "  \"name\": \"p@p.xom\",\n" +
                "  \"nickname\": \"p\",\n" +
                "  \"identities\": [\n" +
                "    {\n" +
                "      \"user_id\": \"53b995f8bce68d9fc900099c\",\n" +
                "      \"provider\": \"auth0\",\n" +
                "      \"connection\": \"Username-Password-Authentication\",\n" +
                "      \"isSocial\": false\n" +
                "    }\n" +
                " ],\n" +
                "  \"created_at\": \"2014-07-06T18:33:49.005Z\",\n" +
                "  \"username\": \"p\",\n" +
                "  \"updated_at\": \"2015-09-30T19:43:48.499Z\"\n" +
                "}";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    public AuthenticationAPIMockServer willReturnPlainTextUnauthorized() {
        server.enqueue(responseWithPlainText("Unauthorized", 401));
        return this;
    }

    public AuthenticationAPIMockServer willReturnTokens() {
        String json = "{\"" +
                "access_token\": \"" + ACCESS_TOKEN + "\"," +
                "\"refresh_token\": \"" + REFRESH_TOKEN + "\"," +
                "\"id_token\":\"" + ID_TOKEN + "\"," +
                "\"token_type\":\"Bearer\"" +
                "}";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    public AuthenticationAPIMockServer willReturnApplicationResponseWithBody(String body, int statusCode) {
        MockResponse response = new MockResponse()
                .setResponseCode(statusCode)
                .addHeader("Content-Type", "application/x-javascript")
                .setBody(body);
        server.enqueue(response);
        return this;
    }

    private MockResponse responseEmpty(int statusCode) {
        return new MockResponse()
                .setResponseCode(statusCode);
    }

    private MockResponse responseWithPlainText(String statusMessage, int statusCode) {
        return new MockResponse()
                .setResponseCode(statusCode)
                .addHeader("Content-Type", "text/plain")
                .setBody(statusMessage);
    }

    private MockResponse responseWithJSON(String json, int statusCode) {
        return new MockResponse()
                .setResponseCode(statusCode)
                .addHeader("Content-Type", "application/json")
                .setBody(json);
    }

}
