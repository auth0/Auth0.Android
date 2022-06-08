package com.auth0.android.provider;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;

import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.when;

@Ignore
public class AuthorizeResultTest {

    private static final int REQUEST_CODE = 11;
    private static final int OTHER_REQUEST_CODE = 12;
    private static final String CALLBACK_URL = "https://my-domain.auth0.com/android/com.auth0.android.lock.app/callback";
    private static final String SAMPLE_HASH = "#access_token=aToken&id_token=iToken&token_type=Bearer&state=randomState";

    private Intent intent;

    @Before
    public void setUp() {
        intent = Mockito.mock(Intent.class);
        Uri data = Uri.parse(CALLBACK_URL + SAMPLE_HASH);
        when(intent.getData()).thenReturn(data);
    }

    @Test
    public void shouldNotBeValidForOtherResult() {
        AuthorizeResult authorizeResult = new AuthorizeResult(REQUEST_CODE, Activity.RESULT_OK, intent);

        boolean isValid = authorizeResult.isValid(OTHER_REQUEST_CODE);

        MatcherAssert.assertThat(isValid, is(false));
    }

    @Test
    public void shouldBeValidAndCanceledForNullUri() {
        when(intent.getData()).thenReturn(null);
        AuthorizeResult authorizeResult = new AuthorizeResult(intent);

        assertThat(authorizeResult.isValid(REQUEST_CODE), is(true));
        assertThat(authorizeResult.isCanceled(), is(true));
    }

    @Test
    public void shouldBeValidForCanceledResult() {
        when(intent.getData()).thenReturn(null);
        AuthorizeResult authorizeResult = new AuthorizeResult(REQUEST_CODE, Activity.RESULT_CANCELED, intent);

        assertThat(authorizeResult.isValid(REQUEST_CODE), is(true));
    }

    @Test
    public void shouldBeValidForExpectedActivityResult() {
        AuthorizeResult authorizeResult = new AuthorizeResult(REQUEST_CODE, Activity.RESULT_OK, intent);

        assertThat(authorizeResult.isValid(REQUEST_CODE), is(true));
    }

    @Test
    public void shouldBeValid() {
        AuthorizeResult authorizeResult = new AuthorizeResult(intent);

        assertThat(authorizeResult.isValid(0), is(true));
    }

    @Test
    public void shouldCreateAValidResultWithOnlyTheIntent() {
        AuthorizeResult authorizeResult = new AuthorizeResult(intent);

        assertThat(authorizeResult.getIntentData(), is(notNullValue()));
        assertThat(authorizeResult.getIntentData(), is(intent.getData()));
        assertThat(authorizeResult.isCanceled(), is(false));
    }
}