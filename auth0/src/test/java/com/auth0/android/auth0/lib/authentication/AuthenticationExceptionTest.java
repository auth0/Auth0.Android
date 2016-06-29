package com.auth0.android.auth0.lib.authentication;

import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static com.auth0.android.auth0.lib.Auth0Exception.UNKNOWN_ERROR;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

@SuppressWarnings("ThrowableInstanceNeverThrown")
public class AuthenticationExceptionTest {

    private static final String CODE_KEY = "code";
    private static final String NAME_KEY = "name";
    private static final String ERROR_KEY = "error";
    private static final String ERROR_DESCRIPTION_KEY = "error_description";
    private static final String DESCRIPTION_KEY = "description";

    private Map<String, Object> values;

    @Before
    public void setUp() throws Exception {
        values = new HashMap<>();
    }

    @Test
    public void shouldGetUnknownCode() throws Exception {
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getCode(), is(equalTo(UNKNOWN_ERROR)));
    }

    @Test
    public void shouldGetPreferErrorOverCode() throws Exception {
        values.put(ERROR_KEY, "a_valid_error");
        values.put(CODE_KEY, "a_valid_code");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getCode(), is(equalTo("a_valid_error")));
    }

    @Test
    public void shouldGetValidCode() throws Exception {
        values.put(CODE_KEY, "a_valid_code");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getCode(), is(equalTo("a_valid_code")));
    }

    @Test
    public void shouldGetValidError() throws Exception {
        values.put(ERROR_KEY, "a_valid_error");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getCode(), is(equalTo("a_valid_error")));
    }


    @Test
    public void shouldGetPreferDescriptionOverErrorDescription() throws Exception {
        values.put(ERROR_DESCRIPTION_KEY, "a_valid_error_description");
        values.put(DESCRIPTION_KEY, "a_valid_description");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo("a_valid_description")));
    }

    @Test
    public void shouldGetValidDescription() throws Exception {
        values.put(DESCRIPTION_KEY, "a_valid_error_description");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo("a_valid_error_description")));
    }

    @Test
    public void shouldGetValidErrorDescription() throws Exception {
        values.put(ERROR_DESCRIPTION_KEY, "a_valid_error_description");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo("a_valid_error_description")));
    }

    @Test
    public void shouldGetPlainTextAsDescription() throws Exception {
        AuthenticationException ex = new AuthenticationException("Payload", 404);
        assertThat(ex.getDescription(), is(equalTo("Payload")));
    }

    @Test
    public void shouldGetMessageWithUnknownCodeIfNullDescription() throws Exception {
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo(String.format("Received error with code %s", UNKNOWN_ERROR))));
    }

    @Test
    public void shouldNotGetEmptyDescription() throws Exception {
        values.put(CODE_KEY, "a_valid_code");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getDescription(), is(equalTo("Failed with unknown error")));
    }

    @Test
    public void shouldGetValuesFromTheMap() throws Exception {
        values.put("key", "value");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.getValue("key"), is(notNullValue()));
        assertThat(ex.getValue("key"), is(instanceOf(String.class)));
        assertThat((String) ex.getValue("key"), is(equalTo("value")));
    }

    @Test
    public void shouldRequireMultifactor() throws Exception {
        values.put(CODE_KEY, "a0.mfa_required");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorRequired(), is(true));
    }

    @Test
    public void shouldRequireMultifactorEnroll() throws Exception {
        values.put(CODE_KEY, "a0.mfa_registration_required");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorEnrollRequired(), is(true));
    }

    @Test
    public void shouldHaveInvalidMultifactorCode() throws Exception {
        values.put(CODE_KEY, "a0.mfa_invalid_code");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isMultifactorCodeInvalid(), is(true));
    }

    @Test
    public void shouldHaveNotStrongPassword() throws Exception {
        values.put(CODE_KEY, "invalid_password");
        values.put(NAME_KEY, "PasswordStrengthError");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isPasswordNotStrongEnough(), is(true));
    }

    @Test
    public void shouldHaveAlreadyUsedPassword() throws Exception {
        values.put(CODE_KEY, "invalid_password");
        values.put(NAME_KEY, "PasswordHistoryError");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isPasswordAlreadyUsed(), is(true));
    }

    @Test
    public void shouldHaveRuleError() throws Exception {
        values.put(CODE_KEY, "unauthorized");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isRuleError(), is(true));
    }

    @Test
    public void shouldHaveInvalidCredentials() throws Exception {
        values.put(CODE_KEY, "invalid_user_password");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isInvalidCredentials(), is(true));
    }

    @Test
    public void shouldHaveAccessDenied() throws Exception {
        values.put(CODE_KEY, "access_denied");
        AuthenticationException ex = new AuthenticationException(values);
        assertThat(ex.isAccessDenied(), is(true));
    }

}