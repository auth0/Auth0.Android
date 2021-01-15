package com.auth0.android.authentication;


import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.collection.IsMapWithSize.anEmptyMap;

public class ParameterBuilderTest {

    public static final String CLIENT_ID = "CLIENT ID";
    public static final String GRANT_TYPE = "password";
    public static final String CONNECTION = "AD";
    public static final String REALM = "users";
    public static final String DEVICE = "ANDROID TEST DEVICE";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();
    private ParameterBuilder builder;

    @Before
    public void setUp() {
        this.builder = ParameterBuilder.newAuthenticationBuilder();
    }

    @Test
    public void shouldInstantiateWithNoArguments() {
        assertThat(ParameterBuilder.newAuthenticationBuilder(), is(notNullValue()));
    }

    @Test
    public void shouldInstantiateWithDefaultScope() {
        assertThat(ParameterBuilder.newAuthenticationBuilder().asDictionary(), hasEntry("scope", ParameterBuilder.SCOPE_OPENID));
    }

    @Test
    public void shouldInstantiateWithArguments() {
        assertThat(ParameterBuilder.newBuilder(new HashMap<String, String>()), is(notNullValue()));
    }

    @Test
    public void shouldSetClientID() {
        assertThat(builder.setClientId(CLIENT_ID).asDictionary(), hasEntry("client_id", CLIENT_ID));
    }

    @Test
    public void shouldSetScope() {
        Map<String, String> parameters = builder.setScope(ParameterBuilder.SCOPE_OFFLINE_ACCESS).asDictionary();
        assertThat(parameters, hasEntry("scope", ParameterBuilder.SCOPE_OFFLINE_ACCESS));
    }

    @Test
    public void shouldSetAudience() {
        Map<String, String> parameters = builder.setAudience("https://domain.auth0.com/api").asDictionary();
        assertThat(parameters, hasEntry("audience", "https://domain.auth0.com/api"));
    }

    @Test
    public void shouldSetRefreshToken() {
        Map<String, String> parameters = builder.setRefreshToken(DEVICE).asDictionary();
        assertThat(parameters, hasEntry("refresh_token", DEVICE));
    }

    @Test
    public void shouldSetScopeWithOfflineAccess() {
        Map<String, String> parameters = builder.setScope(ParameterBuilder.SCOPE_OFFLINE_ACCESS).asDictionary();
        assertThat(parameters, hasEntry("scope", ParameterBuilder.SCOPE_OFFLINE_ACCESS));
    }

    @Test
    public void shouldSetGrantType() {
        assertThat(builder.setGrantType(GRANT_TYPE).asDictionary(), hasEntry("grant_type", GRANT_TYPE));
    }

    @Test
    public void shouldSetConnection() {
        assertThat(builder.setConnection(CONNECTION).asDictionary(), hasEntry("connection", CONNECTION));
    }

    @Test
    public void shouldSetRealm() {
        assertThat(builder.setRealm(REALM).asDictionary(), hasEntry("realm", REALM));
    }

    @Test
    public void shouldAddArbitraryEntry() {
        assertThat(builder.set("key", "value").asDictionary(), hasEntry("key", "value"));
    }

    @Test
    public void shouldNotAddNullEntry() {
        assertThat(builder.set("key", null).asDictionary(), not(hasEntry("key", null)));
    }

    @Test
    public void shouldAddAllFromDictionary() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("key", "value");
        assertThat(builder.addAll(parameters).asDictionary(), hasEntry("key", "value"));
    }

    @Test
    public void shouldSkipNullValuesOnAddAllFromDictionary() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("key", "value");
        parameters.put("null", null);
        assertThat(builder.addAll(parameters).asDictionary(), hasEntry("key", "value"));
        assertThat(builder.addAll(parameters).asDictionary(), not(hasEntry("null", null)));
    }

    @Test
    public void shouldClearAllValues() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("key", "value");
        builder.addAll(parameters);
        assertThat(builder.asDictionary(), hasEntry("key", "value"));
        builder.clearAll();
        assertThat(builder.asDictionary(), anEmptyMap());
    }

    @Test
    public void shouldProvideADictionaryCopy() {
        Map<String, String> parameters = builder.setClientId(CLIENT_ID).asDictionary();
        builder.set("key", "value");
        assertThat(parameters, not(hasEntry("key", "value")));
    }

    @Test
    public void shouldProvideAnImmutableDictionary() {
        Map<String, String> parameters = builder.setClientId(CLIENT_ID).asDictionary();
        try {
            parameters.put("key", "value");
        } catch (Exception e) {
            assertThat(e.getClass().getName(), is(equalTo(UnsupportedOperationException.class.getName())));
        }
    }

    private static Matcher<Map<? extends String, ?>> hasEntry(String key, Object value) {
        return Matchers.hasEntry(key, value);
    }
}
