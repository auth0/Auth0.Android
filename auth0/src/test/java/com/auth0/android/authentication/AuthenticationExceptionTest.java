package com.auth0.android.authentication;

import com.auth0.android.Auth0Exception;
import com.auth0.android.NetworkErrorException;
import com.auth0.android.request.internal.GsonProvider;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

import static com.auth0.android.Auth0Exception.UNKNOWN_ERROR;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21)
public class AuthenticationExceptionTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static final String PASSWORD_STRENGTH_ERROR_RESPONSE = "src/test/resources/password_strength_error.json";
    private static final String CODE_KEY = "code";
    private static final String NAME_KEY = "name";
    private static final String ERROR_KEY = "error";
    private static final String ERROR_DESCRIPTION_KEY = "error_description";
    private static final String DESCRIPTION_KEY = "description";

    private Map<String, Object> values;

    @Before
    public void setUp() {
        values = new HashMap<>();
    }

    @Test
    public void shouldGetUnknownCode() {
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getCode(), is(equalTo(UNKNOWN_ERROR)));
    }

    @Test
    public void shouldGetPreferErrorOverCode() {
        values.put(ERROR_KEY, "a_valid_error");
        values.put(CODE_KEY, "a_valid_code");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getCode(), is(equalTo("a_valid_error")));
    }

    @Test
    public void shouldGetValidCode() {
        values.put(CODE_KEY, "a_valid_code");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getCode(), is(equalTo("a_valid_code")));
    }

    @Test
    public void shouldGetValidError() {
        values.put(ERROR_KEY, "a_valid_error");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getCode(), is(equalTo("a_valid_error")));
    }

    @Test
    public void shouldGetPreferDescriptionOverErrorDescription() {
        values.put(ERROR_DESCRIPTION_KEY, "a_valid_error_description");
        values.put(DESCRIPTION_KEY, "a_valid_description");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo("a_valid_description")));
    }

    @Test
    public void shouldGetValidDescription() {
        values.put(DESCRIPTION_KEY, "a_valid_error_description");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo("a_valid_error_description")));
    }

    @Test
    public void shouldGetValidErrorDescription() {
        values.put(ERROR_DESCRIPTION_KEY, "a_valid_error_description");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo("a_valid_error_description")));
    }

    @Test
    public void shouldGetPlainTextAsDescription() {
        AuthenticationException ex = new AuthenticationException("Payload", 404);
        assertThat(ex.getDescription(), is(equalTo("Payload")));
    }

    @Test
    public void shouldGetMessageWithUnknownCodeIfNullDescription() {
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo(String.format("Received error with code %s", UNKNOWN_ERROR))));
    }

    @Test
    public void shouldNotGetEmptyDescription() {
        values.put(CODE_KEY, "a_valid_code");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo("Failed with unknown error")));
    }

    @Test
    public void shouldGetValuesFromTheMap() {
        values.put("key", "value");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getValue("key"), is(notNullValue()));
        assertThat(ex.getValue("key"), is(instanceOf(String.class)));
        assertThat((String) ex.getValue("key"), is(equalTo("value")));
    }

    @Test
    public void shouldReturnNullIfMapDoesNotExist() {
        AuthenticationException ex1 = new AuthenticationException("code", "description");
        AuthenticationException ex2 = new AuthenticationException("message");
        AuthenticationException ex3 = new AuthenticationException("code", new Auth0Exception("message"));
        AuthenticationException ex4 = new AuthenticationException("credentials", 1);
        assertThat(ex1.getValue("key"), is(nullValue()));
        assertThat(ex2.getValue("key"), is(nullValue()));
        assertThat(ex3.getValue("key"), is(nullValue()));
        assertThat(ex4.getValue("key"), is(nullValue()));
    }

    @Test
    public void shouldNotHaveNetworkError() {
        AuthenticationException ex = new AuthenticationException("Something else happened");
        assertThat(ex.isNetworkError(), is(false));
    }

    @Test
    public void shouldHaveNetworkError() {
        AuthenticationException ex = new AuthenticationException("Request has definitely failed", new NetworkErrorException(new IOException()));
        assertThat(ex.isNetworkError(), is(true));
    }

    @Test
    public void shouldHaveExpiredMultifactorTokenOnOIDCMode() {
        values.put(ERROR_KEY, "expired_token");
        values.put(ERROR_DESCRIPTION_KEY, "mfa_token is expired");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorTokenInvalid(), is(true));
    }

    @Test
    public void shouldHaveMalformedMultifactorTokenOnOIDCMode() {
        values.put(ERROR_KEY, "invalid_grant");
        values.put(ERROR_DESCRIPTION_KEY, "Malformed mfa_token");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorTokenInvalid(), is(true));
    }

    @Test
    public void shouldRequireMultifactorOnOIDCMode() {
        values.put(ERROR_KEY, "mfa_required");
        values.put("mfa_token", "some-random-token");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorRequired(), is(true));
        assertThat((String) ex.getValue("mfa_token"), is("some-random-token"));
    }

    @Test
    public void shouldRequireMultifactor() {
        values.put(CODE_KEY, "a0.mfa_required");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorRequired(), is(true));
    }

    @Test
    public void shouldRequireMultifactorEnrollOnOIDCMode() {
        values.put(ERROR_KEY, "unsupported_challenge_type");
        values.put(ERROR_DESCRIPTION_KEY, "User is not enrolled with guardian");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorEnrollRequired(), is(true));
    }

    @Test
    public void shouldRequireMultifactorEnroll() {
        values.put(CODE_KEY, "a0.mfa_registration_required");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorEnrollRequired(), is(true));
    }

    @Test
    public void shouldHaveInvalidMultifactorCodeOnOIDCMode() {
        values.put(ERROR_KEY, "invalid_grant");
        values.put(ERROR_DESCRIPTION_KEY, "Invalid otp_code.");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorCodeInvalid(), is(true));
    }

    @Test
    public void shouldHaveInvalidMultifactorCode() {
        values.put(CODE_KEY, "a0.mfa_invalid_code");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorCodeInvalid(), is(true));
    }

    @Test
    public void shouldHaveNotStrongPassword() {
        values.put(CODE_KEY, "invalid_password");
        values.put(NAME_KEY, "PasswordStrengthError");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isPasswordNotStrongEnough(), is(true));
    }

    @Test
    public void shouldHaveNotStrongPasswordWithDetailedDescription() throws Exception {
        Gson gson = GsonProvider.buildGson();
        FileReader fr = new FileReader(PASSWORD_STRENGTH_ERROR_RESPONSE);
        Type mapType = new TypeToken<Map<String, Object>>() {
        }.getType();
        Map<String, Object> mapPayload = gson.fromJson(fr, mapType);

        AuthenticationException ex = new AuthenticationException(mapPayload);
        assertThat(ex.isPasswordNotStrongEnough(), is(true));

        String expectedDescription = "At least 10 characters in length; Contain at least 3 of the following 4 types of characters: lower case letters (a-z), upper case letters (A-Z), numbers (i.e. 0-9), special characters (e.g. !@#$%^&*); Should contain: lower case letters (a-z), upper case letters (A-Z), numbers (i.e. 0-9), special characters (e.g. !@#$%^&*); No more than 2 identical characters in a row (e.g., \"aaa\" not allowed)";
        assertThat(ex.getDescription(), is(expectedDescription));
    }

    @Test
    public void shouldHaveAlreadyUsedPassword() {
        values.put(CODE_KEY, "invalid_password");
        values.put(NAME_KEY, "PasswordHistoryError");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isPasswordAlreadyUsed(), is(true));
    }

    @Test
    public void shouldHaveRuleError() {
        values.put(CODE_KEY, "unauthorized");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isRuleError(), is(true));
    }

    @Test
    public void shouldHaveInvalidCredentials() {
        values.put(CODE_KEY, "invalid_user_password");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isInvalidCredentials(), is(true));
    }

    @Test
    public void shouldHaveOIDCInvalidCredentials() {
        values.put(CODE_KEY, "invalid_grant");
        values.put(ERROR_DESCRIPTION_KEY, "Wrong email or password.");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isInvalidCredentials(), is(true));
    }

    @Test
    public void shouldHaveAccessDenied() {
        values.put(CODE_KEY, "access_denied");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isAccessDenied(), is(true));
    }

    @Test
    public void shouldHaveInvalidAuthorizeUrl() {
        values.put(CODE_KEY, "a0.invalid_authorize_url");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isInvalidAuthorizeURL(), is(true));
    }

    @Test
    public void shouldHaveInvalidConfiguration() {
        values.put(CODE_KEY, "a0.invalid_configuration");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isInvalidConfiguration(), is(true));
    }

    @Test
    public void shouldHaveAuthenticationCanceled() {
        values.put(CODE_KEY, "a0.authentication_canceled");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isAuthenticationCanceled(), is(true));
    }

    @Test
    public void shouldHavePasswordLeaked() {
        values.put(CODE_KEY, "password_leaked");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isPasswordLeaked(), is(true));
    }

    @Test
    public void shouldHaveLoginRequired() {
        values.put(CODE_KEY, "login_required");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isLoginRequired(), is(true));
    }

    @Test
    public void shouldHaveMissingBrowserApp() {
        values.put(CODE_KEY, "a0.browser_not_available");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isBrowserAppNotAvailable(), is(true));
    }

}