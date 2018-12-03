package com.auth0.android.util;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

@RunWith(RobolectricTestRunner.class)
public class TelemetryTest {

    private Telemetry telemetry;

    @Before
    public void setUp() throws Exception {
        telemetry = new Telemetry("auth0-java", "1.0.0", "1.2.3");
    }

    @Test
    public void shouldReturnBase64() throws Exception {
        assertThat(telemetry.getValue(), is(notNullValue()));
    }

    //Testing Android version only for a few SDKs

    @Test
    @Config(sdk = 21)
    public void shouldAlwaysIncludeAndroidVersionAPI21() throws Exception {
        telemetry = new Telemetry(null, null);
        assertThat(telemetry.getEnvironment(), is(notNullValue()));
        assertThat(telemetry.getEnvironment().get("android"), is("21"));
    }

    @Test
    @Config(sdk = 23)
    public void shouldAlwaysIncludeAndroidVersionAPI23() throws Exception {
        telemetry = new Telemetry(null, null);
        assertThat(telemetry.getEnvironment(), is(notNullValue()));
        assertThat(telemetry.getEnvironment().get("android"), is("23"));
    }

    @Test
    public void shouldNotIncludeCoreIfNotProvided() throws Exception {
        telemetry = new Telemetry(null, null);
        assertThat(telemetry.getEnvironment(), is(notNullValue()));
        assertThat(telemetry.getEnvironment().containsKey("core"), is(false));
    }

    @Test
    public void shouldGetName() throws Exception {
        assertThat(telemetry.getName(), is("auth0-java"));
    }

    @Test
    public void shouldGetVersion() throws Exception {
        assertThat(telemetry.getVersion(), is("1.0.0"));
    }

    @Test
    public void shouldGetLibraryVersion() throws Exception {
        assertThat(telemetry.getLibraryVersion(), is("1.2.3"));
        assertThat(telemetry.getEnvironment().get("core"), is("1.2.3"));
    }

    @Test
    public void shouldGenerateNotNullTelemetryValue() throws Exception {
        assertThat(telemetry.getValue(), is(notNullValue()));
    }
}