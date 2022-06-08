package com.auth0.android.util;

import android.util.Base64;

import com.auth0.android.auth0.BuildConfig;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

@Ignore
public class Auth0UserAgentTest {

    //Testing Android version only for a few SDKs

    @Test
    @Config(sdk = 21)
    public void shouldAlwaysIncludeAndroidVersionAPI21() {
        Auth0UserAgent auth0UserAgent = new Auth0UserAgent("auth0-java", "1.2.3");
        assertThat(auth0UserAgent.getEnvironment(), is(notNullValue()));
        assertThat(auth0UserAgent.getEnvironment().get("android"), is("21"));
    }

    @Test
    @Config(sdk = 23)
    public void shouldAlwaysIncludeAndroidVersionAPI23() {
        Auth0UserAgent auth0UserAgent = new Auth0UserAgent("auth0-java", "1.2.3");
        assertThat(auth0UserAgent.getEnvironment(), is(notNullValue()));
        assertThat(auth0UserAgent.getEnvironment().get("android"), is("23"));
    }

    @Test
    public void shouldUseDefaultValuesWithDefaultConstructor() {
        Auth0UserAgent auth0UserAgent = new Auth0UserAgent();
        assertThat(auth0UserAgent.getValue(), is(notNullValue()));
        assertThat(auth0UserAgent.getName(), is(BuildConfig.LIBRARY_NAME));
        assertThat(auth0UserAgent.getVersion(), is(BuildConfig.VERSION_NAME));
        assertThat(auth0UserAgent.getEnvironment(), is(notNullValue()));
        assertThat(auth0UserAgent.getLibraryVersion(), is(nullValue()));
    }

    @Test
    public void shouldUseDefaultNameEmpty() {
        Auth0UserAgent auth0UserAgent = new Auth0UserAgent("", "2.0");
        assertThat(auth0UserAgent.getValue(), is(notNullValue()));
        assertThat(auth0UserAgent.getName(), is(BuildConfig.LIBRARY_NAME));
        assertThat(auth0UserAgent.getVersion(), is("2.0"));
        assertThat(auth0UserAgent.getEnvironment(), is(notNullValue()));
        assertThat(auth0UserAgent.getLibraryVersion(), is(nullValue()));
    }

    @Test
    public void shouldUseDefaultVersionIfEmpty() {
        Auth0UserAgent auth0UserAgent = new Auth0UserAgent("auth0-java", "");
        assertThat(auth0UserAgent.getValue(), is(notNullValue()));
        assertThat(auth0UserAgent.getName(), is("auth0-java"));
        assertThat(auth0UserAgent.getVersion(), is(BuildConfig.VERSION_NAME));
        assertThat(auth0UserAgent.getEnvironment(), is(notNullValue()));
        assertThat(auth0UserAgent.getLibraryVersion(), is(nullValue()));
    }

    @Test
    public void shouldNotIncludeLibraryVersionIfNotProvided() {
        Auth0UserAgent auth0UserAgent = new Auth0UserAgent();
        assertThat(auth0UserAgent.getEnvironment(), is(notNullValue()));
        assertThat(auth0UserAgent.getEnvironment().containsKey("auth0.android"), is(false));
    }

    @Test
    public void shouldGetName() {
        Auth0UserAgent auth0UserAgent = new Auth0UserAgent("auth0-java", "1.0.0", "1.2.3");
        assertThat(auth0UserAgent.getName(), is("auth0-java"));
    }

    @Test
    public void shouldGetVersion() {
        Auth0UserAgent auth0UserAgent = new Auth0UserAgent("auth0-java", "1.0.0", "1.2.3");
        assertThat(auth0UserAgent.getVersion(), is("1.0.0"));
    }

    @Test
    public void shouldGetLibraryVersion() {
        Auth0UserAgent auth0UserAgent = new Auth0UserAgent("auth0-java", "1.0.0", "1.2.3");
        assertThat(auth0UserAgent.getLibraryVersion(), is("1.2.3"));
        assertThat(auth0UserAgent.getEnvironment().get("auth0.android"), is("1.2.3"));
    }

    @Test
    @Config(sdk = 23)
    public void shouldGenerateCompleteTelemetryBase64Value() {
        Gson gson = new Gson();
        Type mapType = new TypeToken<Map<String, Object>>() {
        }.getType();

        Auth0UserAgent auth0UserAgentComplete = new Auth0UserAgent("auth0-java", "1.0.0", "1.2.3");
        String value = auth0UserAgentComplete.getValue();
        assertThat(value, is("eyJuYW1lIjoiYXV0aDAtamF2YSIsImVudiI6eyJhbmRyb2lkIjoiMjMiLCJhdXRoMC5hbmRyb2lkIjoiMS4yLjMifSwidmVyc2lvbiI6IjEuMC4wIn0="));
        String completeString = new String(Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP), StandardCharsets.UTF_8);
        Map<String, Object> complete = gson.fromJson(completeString, mapType);
        assertThat((String) complete.get("name"), is("auth0-java"));
        assertThat((String) complete.get("version"), is("1.0.0"));
        Map<String, Object> completeEnv = (Map<String, Object>) complete.get("env");
        assertThat((String) completeEnv.get("auth0.android"), is("1.2.3"));
        assertThat((String) completeEnv.get("android"), is("23"));
    }

    @Test
    @Config(sdk = 23)
    public void shouldGenerateBasicTelemetryBase64Value() {
        Gson gson = new Gson();
        Type mapType = new TypeToken<Map<String, Object>>() {
        }.getType();

        Auth0UserAgent auth0UserAgentBasic = new Auth0UserAgent("auth0-python", "99.3.1");
        String value = auth0UserAgentBasic.getValue();
        assertThat(value, is("eyJuYW1lIjoiYXV0aDAtcHl0aG9uIiwiZW52Ijp7ImFuZHJvaWQiOiIyMyJ9LCJ2ZXJzaW9uIjoiOTkuMy4xIn0="));
        String basicString = new String(Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP), StandardCharsets.UTF_8);
        Map<String, Object> basic = gson.fromJson(basicString, mapType);
        assertThat((String) basic.get("name"), is("auth0-python"));
        assertThat((String) basic.get("version"), is("99.3.1"));
        Map<String, Object> basicEnv = (Map<String, Object>) basic.get("env");
        assertThat(basicEnv.get("auth0.android"), is(nullValue()));
        assertThat((String) basicEnv.get("android"), is("23"));
    }
}