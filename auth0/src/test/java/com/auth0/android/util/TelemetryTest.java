package com.auth0.android.util;

import android.util.Base64;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.lang.reflect.Type;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

@RunWith(RobolectricTestRunner.class)
public class TelemetryTest {

    //Testing Android version only for a few SDKs

    @Test
    @Config(sdk = 21)
    public void shouldAlwaysIncludeAndroidVersionAPI21() throws Exception {
        Telemetry telemetry = new Telemetry(null, null);
        assertThat(telemetry.getEnvironment(), is(notNullValue()));
        assertThat(telemetry.getEnvironment().get("android"), is("21"));
    }

    @Test
    @Config(sdk = 23)
    public void shouldAlwaysIncludeAndroidVersionAPI23() throws Exception {
        Telemetry telemetry = new Telemetry(null, null);
        assertThat(telemetry.getEnvironment(), is(notNullValue()));
        assertThat(telemetry.getEnvironment().get("android"), is("23"));
    }

    @Test
    public void shouldNotIncludeCoreIfNotProvided() throws Exception {
        Telemetry telemetry = new Telemetry(null, null);
        assertThat(telemetry.getEnvironment(), is(notNullValue()));
        assertThat(telemetry.getEnvironment().containsKey("core"), is(false));
    }

    @Test
    public void shouldGetName() throws Exception {
        Telemetry telemetry = new Telemetry("auth0-java", "1.0.0", "1.2.3");
        assertThat(telemetry.getName(), is("auth0-java"));
    }

    @Test
    public void shouldGetVersion() throws Exception {
        Telemetry telemetry = new Telemetry("auth0-java", "1.0.0", "1.2.3");
        assertThat(telemetry.getVersion(), is("1.0.0"));
    }

    @Test
    public void shouldGetLibraryVersion() throws Exception {
        Telemetry telemetry = new Telemetry("auth0-java", "1.0.0", "1.2.3");
        assertThat(telemetry.getLibraryVersion(), is("1.2.3"));
        assertThat(telemetry.getEnvironment().get("core"), is("1.2.3"));
    }

    @Test
    @Config(sdk = 23)
    public void shouldGenerateCompleteTelemetryBase64Value() throws Exception {
        Gson gson = new Gson();
        Type mapType = new TypeToken<Map<String, Object>>() {
        }.getType();

        Telemetry telemetryComplete = new Telemetry("auth0-java", "1.0.0", "1.2.3");
        String value = telemetryComplete.getValue();
        assertThat(value, is("eyJuYW1lIjoiYXV0aDAtamF2YSIsImVudiI6eyJjb3JlIjoiMS4yLjMiLCJhbmRyb2lkIjoiMjMifSwidmVyc2lvbiI6IjEuMC4wIn0="));
        String completeString = new String(Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP), "UTF-8");
        Map<String, Object> complete = gson.fromJson(completeString, mapType);
        assertThat((String) complete.get("name"), is("auth0-java"));
        assertThat((String) complete.get("version"), is("1.0.0"));
        Map<String, Object> completeEnv = (Map<String, Object>) complete.get("env");
        assertThat((String) completeEnv.get("core"), is("1.2.3"));
        assertThat((String) completeEnv.get("android"), is("23"));
    }

    @Test
    @Config(sdk = 23)
    public void shouldGenerateBasicTelemetryBase64Value() throws Exception {
        Gson gson = new Gson();
        Type mapType = new TypeToken<Map<String, Object>>() {
        }.getType();

        Telemetry telemetryBasic = new Telemetry("auth0-python", "99.3.1");
        String value = telemetryBasic.getValue();
        assertThat(value, is("eyJuYW1lIjoiYXV0aDAtcHl0aG9uIiwiZW52Ijp7ImFuZHJvaWQiOiIyMyJ9LCJ2ZXJzaW9uIjoiOTkuMy4xIn0="));
        String basicString = new String(Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP), "UTF-8");
        Map<String, Object> basic = gson.fromJson(basicString, mapType);
        assertThat((String) basic.get("name"), is("auth0-python"));
        assertThat((String) basic.get("version"), is("99.3.1"));
        Map<String, Object> basicEnv = (Map<String, Object>) basic.get("env");
        assertThat(basicEnv.get("core"), is(nullValue()));
        assertThat((String) basicEnv.get("android"), is("23"));
    }

    @Test
    @Config(sdk = 21)
    public void shouldGenerateRegularTelemetryBase64Value() throws Exception {
        Gson gson = new Gson();
        Type mapType = new TypeToken<Map<String, Object>>() {
        }.getType();

        Telemetry telemetryRegular = new Telemetry(null, null);
        String value = telemetryRegular.getValue();
        assertThat(value, is("eyJlbnYiOnsiYW5kcm9pZCI6IjIxIn19"));
        String defaultString = new String(Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP), "UTF-8");
        Map<String, Object> regular = gson.fromJson(defaultString, mapType);
        assertThat(regular.get("name"), is(nullValue()));
        assertThat(regular.get("version"), is(nullValue()));
        Map<String, Object> regularEnv = (Map<String, Object>) regular.get("env");
        assertThat(regularEnv.get("core"), is(nullValue()));
        assertThat((String) regularEnv.get("android"), is("21"));
    }
}