/*
 * AuthenticationAPI.java
 *
 * Copyright (c) 2015 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.auth0.android.auth0.lib.util;

import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;

import java.io.IOException;

public class UsersAPI {

    private MockWebServer server;

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

    public UsersAPI willReturnFailedLink() {
        String json = "";
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
