package com.auth0.android.util;

import java.io.IOException;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

public class UsersAPI {

    private final MockWebServer server;

    public UsersAPI() throws IOException {
        this.server = new MockWebServer();
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

    public UsersAPI willReturnSuccessfulUnlink() {
        String json = "[\n" +
                "  {\n" +
                "    \"profileData\": {\n" +
                "      \"email\": \"asd@asd.asd\",\n" +
                "      \"email_verified\": true,\n" +
                "      \"nickname\": \"asdasd\",\n" +
                "      \"username\": \"asdasd\"\n" +
                "    },\n" +
                "    \"user_id\": \"123d123d123d123d123d123d\",\n" +
                "    \"provider\": \"auth0\",\n" +
                "    \"connection\": \"Username-Password-Authentication\",\n" +
                "    \"isSocial\": false\n" +
                "  }\n" +
                "]";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    public UsersAPI willReturnSuccessfulLink() {
        String json = "[\n" +
                "  {\n" +
                "    \"profileData\": {\n" +
                "      \"email\": \"asd@asd.asd\",\n" +
                "      \"email_verified\": true,\n" +
                "      \"nickname\": \"asdasd\",\n" +
                "      \"username\": \"asdasd\"\n" +
                "    },\n" +
                "    \"user_id\": \"5751d11a85a56dd86c460726\",\n" +
                "    \"provider\": \"auth0\",\n" +
                "    \"connection\": \"Username-Password-Authentication\",\n" +
                "    \"isSocial\": false\n" +
                "  },\n" +
                "  {\n" +
                "    \"profileData\": {\n" +
                "      \"name\": \"Asdasd️\",\n" +
                "      \"picture\": \"https://pbs.twimg.com/profile_images/some_invalid.jpeg\",\n" +
                "      \"created_at\": \"Fri May 20 17:13:23 +0000 2011\",\n" +
                "      \"description\": \"Something about us.\",\n" +
                "      \"lang\": \"es\",\n" +
                "      \"location\": \"Buenos Aires\",\n" +
                "      \"screen_name\": \"Aassdd\",\n" +
                "      \"time_zone\": \"Buenos Aires\",\n" +
                "      \"utc_offset\": -10800\n" +
                "    },\n" +
                "    \"access_token\": \"302132759-7CqPgySk321gltiQA2r4XC9byqWvxNdSPdM8Wzvu\",\n" +
                "    \"access_token_secret\": \"mYL3hcGKr6TrClvddSKapMJqsiSHKPwsdmAaOsdaRRbPYTm\",\n" +
                "    \"provider\": \"twitter\",\n" +
                "    \"user_id\": \"30303030\",\n" +
                "    \"connection\": \"twitter\",\n" +
                "    \"isSocial\": true\n" +
                "  }\n" +
                "]";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    public UsersAPI willReturnUserProfile() {
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
                "  \"user_metadata\": \n" +
                "    {\n" +
                "      \"name\": \"name\",\n" +
                "      \"surname\": \"surname\"\n" +
                "    },\n" +
                "  \"created_at\": \"2014-07-06T18:33:49.005Z\",\n" +
                "  \"username\": \"p\",\n" +
                "  \"updated_at\": \"2015-09-30T19:43:48.499Z\"\n" +
                "}";
        server.enqueue(responseWithJSON(json, 200));
        return this;
    }

    private MockResponse responseWithJSON(String json, int statusCode) {
        return new MockResponse()
                .setResponseCode(statusCode)
                .addHeader("Content-Type", "application/json")
                .setBody(json);
    }

}
