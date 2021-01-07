package com.auth0.android.provider

import android.app.Activity
import android.app.Dialog
import android.content.Intent
import android.content.ServiceConnection
import android.net.Uri
import android.os.Parcelable
import androidx.test.espresso.intent.matcher.IntentMatchers
import androidx.test.espresso.intent.matcher.UriMatchers
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.MockAuth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.provider.CustomTabsOptions
import com.auth0.android.provider.PKCE
import com.auth0.android.provider.WebAuthProvider.login
import com.auth0.android.provider.WebAuthProvider.logout
import com.auth0.android.provider.WebAuthProvider.resume
import com.auth0.android.request.DefaultClient
import com.auth0.android.request.HttpMethod.POST
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse
import com.auth0.android.request.internal.ThreadSwitcherShadow
import com.auth0.android.result.Credentials
import com.auth0.android.util.AuthCallbackMatcher
import com.auth0.android.util.AuthenticationAPI
import com.auth0.android.util.MockAuthCallback
import com.nhaarman.mockitokotlin2.KArgumentCaptor
import com.nhaarman.mockitokotlin2.argumentCaptor
import com.nhaarman.mockitokotlin2.eq
import com.nhaarman.mockitokotlin2.verify
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers
import org.hamcrest.collection.IsMapContaining
import org.hamcrest.core.Is.`is`
import org.hamcrest.core.IsEqual.equalTo
import org.hamcrest.core.IsNot.not
import org.hamcrest.core.IsNull.notNullValue
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.*
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.`when`
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLooper
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Paths
import java.util.*

@RunWith(RobolectricTestRunner::class)
@Config(shadows = [ThreadSwitcherShadow::class])
public class WebAuthProviderTest {
    @Mock
    private lateinit var callback: AuthCallback

    @Mock
    private lateinit var voidCallback: VoidCallback
    private lateinit var activity: Activity
    private lateinit var account: Auth0

    private val auth0ExceptionCaptor: KArgumentCaptor<Auth0Exception> = argumentCaptor()

    private val authExceptionCaptor: KArgumentCaptor<AuthenticationException> = argumentCaptor()

    private val intentCaptor: KArgumentCaptor<Intent> = argumentCaptor()

    private val callbackCaptor: KArgumentCaptor<AuthCallback> = argumentCaptor()

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        activity = Mockito.spy(Robolectric.buildActivity(Activity::class.java).get())
        account = Auth0(JwtTestUtils.EXPECTED_AUDIENCE, JwtTestUtils.EXPECTED_BASE_DOMAIN)

        //Next line is needed to avoid CustomTabService from being bound to Test environment
        Mockito.doReturn(false).`when`(activity).bindService(
            com.nhaarman.mockitokotlin2.any<Intent>(),
            com.nhaarman.mockitokotlin2.any<ServiceConnection>(),
            ArgumentMatchers.anyInt()
        )
        BrowserPickerTest.setupBrowserContext(
            activity,
            Arrays.asList("com.auth0.browser"),
            null,
            null
        )
    }

    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//
    //** LOG IN  FEATURE **//
    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//
    @Test
    public fun shouldLoginWithAccount() {
        login(account)
            .start(activity, callback)
        Assert.assertNotNull(WebAuthProvider.managerInstance)
    }

    //scheme
    @Test
    public fun shouldHaveDefaultSchemeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithName("redirect_uri"))
        val redirectUri = Uri.parse(uri?.getQueryParameter("redirect_uri"))
        MatcherAssert.assertThat(redirectUri, UriMatchers.hasScheme("https"))
    }

    @Test
    public fun shouldSetSchemeOnLogin() {
        login(account)
            .withScheme("myapp")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithName("redirect_uri"))
        val redirectUri = Uri.parse(uri?.getQueryParameter("redirect_uri"))
        MatcherAssert.assertThat(redirectUri, UriMatchers.hasScheme("myapp"))
    }

    //connection
    @Test
    public fun shouldNotHaveDefaultConnectionOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, not(UriMatchers.hasParamWithName("connection")))
    }

    @Test
    public fun shouldSetConnectionFromParametersOnLogin() {
        val parameters = Collections.singletonMap("connection", "my-connection" as Any)
        login(account)
            .withConnection("some-connection")
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("connection", "my-connection"))
    }

    @Test
    public fun shouldSetConnectionFromSetterOnLogin() {
        val parameters = Collections.singletonMap("connection", "my-connection" as Any)
        login(account)
            .withParameters(parameters)
            .withConnection("some-connection")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("connection", "some-connection")
        )
    }

    @Test
    public fun shouldNotOverrideConnectionValueWithDefaultConnectionOnLogin() {
        val parameters = Collections.singletonMap("connection", "my-connection" as Any)
        login(account)
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("connection", "my-connection"))
    }

    @Test
    public fun shouldSetConnectionOnLogin() {
        login(account)
            .withConnection("some-connection")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("connection", "some-connection")
        )
    }

    //audience
    @Test
    public fun shouldNotHaveDefaultAudienceOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, not(UriMatchers.hasParamWithName("audience")))
    }

    @Test
    public fun shouldSetAudienceFromParametersOnLogin() {
        val parameters =
            Collections.singletonMap("audience", "https://mydomain.auth0.com/myapi" as Any)
        login(account)
            .withAudience("https://google.com/apis")
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("audience", "https://mydomain.auth0.com/myapi")
        )
    }

    @Test
    public fun shouldSetAudienceFromSetterOnLogin() {
        val parameters =
            Collections.singletonMap("audience", "https://mydomain.auth0.com/myapi" as Any)
        login(account)
            .withParameters(parameters)
            .withAudience("https://google.com/apis")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("audience", "https://google.com/apis")
        )
    }

    @Test
    public fun shouldNotOverrideAudienceValueWithDefaultAudienceOnLogin() {
        val parameters =
            Collections.singletonMap("audience", "https://mydomain.auth0.com/myapi" as Any)
        login(account)
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("audience", "https://mydomain.auth0.com/myapi")
        )
    }

    @Test
    public fun shouldSetAudienceOnLogin() {
        login(account)
            .withAudience("https://google.com/apis")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("audience", "https://google.com/apis")
        )
    }

    //scope
    @Test
    public fun shouldHaveDefaultScopeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("scope", "openid"))
    }

    @Test
    public fun shouldSetScopeFromParametersOnLogin() {
        val parameters = Collections.singletonMap("scope", "openid email contacts" as Any)
        login(account)
            .withScope("profile super_scope")
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("scope", "openid email contacts")
        )
    }

    @Test
    public fun shouldSetScopeFromSetterOnLogin() {
        val parameters = Collections.singletonMap("scope", "openid email contacts" as Any)
        login(account)
            .withParameters(parameters)
            .withScope("profile super_scope")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("scope", "profile super_scope"))
    }

    @Test
    public fun shouldNotOverrideScopeValueWithDefaultScopeOnLogin() {
        val parameters = Collections.singletonMap("scope", "openid email contacts" as Any)
        login(account)
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("scope", "openid email contacts")
        )
    }

    @Test
    public fun shouldSetScopeOnLogin() {
        login(account)
            .withScope("profile super_scope")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("scope", "profile super_scope"))
    }

    //connection scope
    @Test
    public fun shouldNotHaveDefaultConnectionScopeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            not(UriMatchers.hasParamWithName("connection_scope"))
        )
    }

    @Test
    public fun shouldSetConnectionScopeFromParametersOnLogin() {
        val parameters =
            Collections.singletonMap("connection_scope", "openid,email,contacts" as Any)
        login(account)
            .withConnectionScope("profile", "super_scope")
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("connection_scope", "openid,email,contacts")
        )
    }

    @Test
    public fun shouldSetConnectionScopeFromSetterOnLogin() {
        val parameters =
            Collections.singletonMap("connection_scope", "openid,email,contacts" as Any)
        login(account)
            .withParameters(parameters)
            .withConnectionScope("profile", "super_scope")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("connection_scope", "profile,super_scope")
        )
    }

    @Test
    public fun shouldNotOverrideConnectionScopeValueWithDefaultConnectionScopeOnLogin() {
        val parameters =
            Collections.singletonMap("connection_scope", "openid,email,contacts" as Any)
        login(account)
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("connection_scope", "openid,email,contacts")
        )
    }

    @Test
    public fun shouldSetConnectionScopeOnLogin() {
        login(account)
            .withConnectionScope("the", "scope", "of", "my", "connection")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("connection_scope", "the,scope,of,my,connection")
        )
    }

    //state
    @Test
    public fun shouldHaveDefaultStateOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri, UriMatchers.hasParamWithValue(
                `is`("state"), not(
                    Matchers.isEmptyOrNullString()
                )
            )
        )
    }

    @Test
    public fun shouldSetNonNullStateOnLogin() {
        login(account)
            .withState("")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri, UriMatchers.hasParamWithValue(
                `is`("state"), not(
                    Matchers.isEmptyOrNullString()
                )
            )
        )
    }

    @Test
    public fun shouldSetStateFromParametersOnLogin() {
        val parameters = Collections.singletonMap("state", "1234567890" as Any)
        login(account)
            .withState("abcdefg")
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("state", "1234567890"))
    }

    @Test
    public fun shouldSetStateFromSetterOnLogin() {
        val parameters = Collections.singletonMap("state", "1234567890" as Any)
        login(account)
            .withParameters(parameters)
            .withState("abcdefg")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("state", "abcdefg"))
    }

    @Test
    public fun shouldNotOverrideStateValueWithDefaultStateOnLogin() {
        val parameters = Collections.singletonMap("state", "1234567890" as Any)
        login(account)
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("state", "1234567890"))
    }

    @Test
    public fun shouldSetStateOnLogin() {
        login(account)
            .withState("abcdefg")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("state", "abcdefg"))
    }

    //nonce
    @Test
    public fun shouldSetNonceByDefaultIfResponseTypeIncludesCodeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithName("nonce"))
    }

    @Test
    public fun shouldSetNonNullNonceOnLogin() {
        login(account)
            .withNonce("")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri, UriMatchers.hasParamWithValue(
                `is`("nonce"), not(
                    Matchers.isEmptyOrNullString()
                )
            )
        )
    }

    @Test
    public fun shouldSetUserNonceIfResponseTypeIsCodeOnLogin() {
        login(account)
            .withNonce("1234567890")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("nonce", "1234567890"))
    }

    @Test
    public fun shouldSetNonceFromParametersOnLogin() {
        val parameters = Collections.singletonMap("nonce", "1234567890" as Any)
        login(account)
            .withNonce("abcdefg")
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("nonce", "1234567890"))
    }

    @Test
    public fun shouldSetNonceFromSetterOnLogin() {
        val parameters = Collections.singletonMap("nonce", "1234567890" as Any)
        login(account)
            .withParameters(parameters)
            .withNonce("abcdefg")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("nonce", "abcdefg"))
    }

    @Test
    public fun shouldNotOverrideNonceValueWithDefaultNonceOnLogin() {
        val parameters = Collections.singletonMap("nonce", "1234567890" as Any)
        login(account)
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("nonce", "1234567890"))
    }

    @Test
    public fun shouldSetNonceOnLogin() {
        login(account)
            .withNonce("abcdefg")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("nonce", "abcdefg"))
    }

    @Test
    public fun shouldGenerateRandomStringIfDefaultValueIsMissingOnLogin() {
        login(account)
            .start(activity, callback)
        val random1 = OAuthManager.getRandomString(null)
        val random2 = OAuthManager.getRandomString(null)
        MatcherAssert.assertThat(random1, `is`(notNullValue()))
        MatcherAssert.assertThat(random2, `is`(notNullValue()))
        MatcherAssert.assertThat(
            random1,
            `is`(not(equalTo(random2)))
        )
    }

    @Test
    public fun shouldNotGenerateRandomStringIfDefaultValuePresentOnLogin() {
        login(account)
            .start(activity, callback)
        val random1 = OAuthManager.getRandomString("some")
        val random2 = OAuthManager.getRandomString("some")
        MatcherAssert.assertThat(random1, `is`("some"))
        MatcherAssert.assertThat(random2, `is`("some"))
    }

    // max_age
    @Test
    public fun shouldNotSetMaxAgeByDefaultOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, not(UriMatchers.hasParamWithName("max_age")))
    }

    @Test
    public fun shouldSetMaxAgeFromParametersOnLogin() {
        val parameters = Collections.singletonMap("max_age", "09876" as Any)
        login(account)
            .withMaxAge(12345)
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("max_age", "09876"))
    }

    @Test
    public fun shouldSetMaxAgeFromSetterOnLogin() {
        val parameters = Collections.singletonMap("max_age", "09876" as Any)
        login(account)
            .withParameters(parameters)
            .withMaxAge(12345)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("max_age", "12345"))
    }

    // auth0 related
    @Test
    public fun shouldHaveClientIdOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("client_id", "__test_client_id__")
        )
    }

    @Test
    public fun shouldHaveTelemetryInfoOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri, UriMatchers.hasParamWithValue(
                `is`("auth0Client"), not(
                    Matchers.isEmptyOrNullString()
                )
            )
        )
    }

    @Test
    public fun shouldHaveRedirectUriOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri?.getQueryParameter("redirect_uri"),
            `is`("https://test.domain.com/android/com.auth0.android.auth0.test/callback")
        )
    }

    @Test
    public fun shouldSetRedirectUriIgnoringSchemeOnLogin() {
        login(account)
            .withScheme("https")
            .withRedirectUri("myapp://app.company.com/mobile/callback")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri?.getQueryParameter("redirect_uri"),
            `is`("myapp://app.company.com/mobile/callback")
        )
    }

    //response type
    @Test
    public fun shouldHaveDefaultResponseTypeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("response_type", "code"))
    }

    @Test
    public fun shouldSetResponseTypeCodeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("response_type", "code"))
    }

    @Test
    public fun shouldSetNonNullAuthenticationParametersOnLogin() {
        val parameters: MutableMap<String, Any?> = HashMap()
        parameters["a"] = "valid"
        parameters["b"] = null
        login(account)
            .withParameters(parameters)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("a", "valid"))
        MatcherAssert.assertThat(uri, not(UriMatchers.hasParamWithName("b")))
    }

    @Test
    public fun shouldBuildAuthorizeURIWithoutNullsOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        val params = uri!!.queryParameterNames
        for (name in params) {
            MatcherAssert.assertThat(
                uri,
                not(UriMatchers.hasParamWithValue(name, null))
            )
            MatcherAssert.assertThat(
                uri,
                not(UriMatchers.hasParamWithValue(name, "null"))
            )
        }
    }

    @Test
    public fun shouldBuildAuthorizeURIWithCorrectSchemeHostAndPathOnLogin() {
        login(account)
            .withState("a-state")
            .withNonce("a-nonce")
            .start(activity, callback)
        val baseUriString = Uri.parse(account.authorizeUrl)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasScheme(baseUriString.scheme))
        MatcherAssert.assertThat(uri, UriMatchers.hasHost(baseUriString.host))
        MatcherAssert.assertThat(uri, UriMatchers.hasPath(baseUriString.path))
    }

    @Test
    public fun shouldBuildAuthorizeURIWithResponseTypeCodeOnLogin() {
        login(account)
            .withState("a-state")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithName("nonce"))
        MatcherAssert.assertThat(
            uri, UriMatchers.hasParamWithValue(
                `is`("code_challenge"), not(
                    Matchers.isEmptyOrNullString()
                )
            )
        )
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("code_challenge_method", "S256")
        )
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithValue("response_type", "code"))
    }

    @Test
    public fun shouldStartLoginWithBrowserCustomTabsOptions() {
        val options: CustomTabsOptions = CustomTabsOptions.newBuilder().build()
        login(account)
            .withCustomTabsOptions(options)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val intent = intentCaptor.firstValue
        MatcherAssert.assertThat(intent, `is`(notNullValue()))
        MatcherAssert.assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        MatcherAssert.assertThat(intent, IntentMatchers.hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        MatcherAssert.assertThat(intent.data, `is`(CoreMatchers.nullValue()))
        val extras = intentCaptor.firstValue.extras
        MatcherAssert.assertThat<Any?>(
            extras?.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), `is`(
                notNullValue()
            )
        )
        MatcherAssert.assertThat(
            extras?.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS),
            `is`(true)
        )
        MatcherAssert.assertThat(
            extras?.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS) as? CustomTabsOptions,
            `is`(options)
        )
    }

    @Test
    public fun shouldStartLoginWithValidRequestCode() {
        val credentials = Mockito.mock(
            Credentials::class.java
        )
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        Mockito.doAnswer {
            callback.onSuccess(credentials)
            null
        }.`when`(pkce)
            .getToken(anyString(), eq(callback))
        login(account)
            .withPKCE(pkce)
            .start(activity, callback)
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                "1234567890",
                null,
                null,
                "1234"
            )
        )
        val DEFAULT_REQUEST_CODE = 110
        Assert.assertTrue(resume(intent))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginWithIntentWithCodeGrant() {
        val expiresAt = Date()
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        MatcherAssert.assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        MatcherAssert.assertThat(
            sentNonce,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                sentState,
                null,
                null,
                "1234"
            )
        )
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["nonce"] = sentNonce
        jwtBody["aud"] = proxyAccount.clientId
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val codeCredentials = Credentials(
            expectedIdToken,
            "codeAccess",
            "codeType",
            "codeRefresh",
            expiresAt,
            "codeScope"
        )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasCredentials())
        val credentials = authCallback.credentials
        MatcherAssert.assertThat(credentials, `is`(notNullValue()))
        MatcherAssert.assertThat(credentials.idToken, `is`(expectedIdToken))
        MatcherAssert.assertThat(credentials.accessToken, `is`("codeAccess"))
        MatcherAssert.assertThat(credentials.refreshToken, `is`("codeRefresh"))
        MatcherAssert.assertThat(credentials.type, `is`("codeType"))
        MatcherAssert.assertThat(credentials.expiresAt, `is`(expiresAt))
        MatcherAssert.assertThat(credentials.scope, `is`("codeScope"))
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginWithCustomNetworkingClient() {
        val networkingClient: NetworkingClient = Mockito.spy(DefaultClient(10))
        val authCallback = MockAuthCallback()

        // 1. start the webauth flow. the browser would open
        val proxyAccount = Auth0(JwtTestUtils.EXPECTED_AUDIENCE, JwtTestUtils.EXPECTED_BASE_DOMAIN)
        login(proxyAccount)
            .withNetworkingClient(networkingClient)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS

        // 2. capture the intent filter to obtain the state and nonce sent
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        MatcherAssert.assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        MatcherAssert.assertThat(
            sentNonce,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                sentState,
                null,
                null,
                "1234"
            )
        )
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["nonce"] = sentNonce
        jwtBody["aud"] = proxyAccount.clientId
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)

        // 3. craft a code response with a valid ID token
        val jsonResponse = "{\"id_token\":\"$expectedIdToken\"}"
        val codeInputStream: InputStream = ByteArrayInputStream(jsonResponse.toByteArray())
        val codeResponse = ServerResponse(200, codeInputStream, emptyMap())
        Mockito.doReturn(codeResponse).`when`(networkingClient).load(
            com.nhaarman.mockitokotlin2.eq(proxyAccount.getDomainUrl() + "oauth/token"),
            com.nhaarman.mockitokotlin2.any<RequestOptions>()
        )

        // 4. craft a JWKS response with expected keys
        val encoded = Files.readAllBytes(Paths.get("src/test/resources/rsa_jwks.json"))
        val jwksInputStream: InputStream = ByteArrayInputStream(encoded)
        val jwksResponse = ServerResponse(200, jwksInputStream, emptyMap())
        Mockito.doReturn(jwksResponse).`when`(networkingClient).load(
            com.nhaarman.mockitokotlin2.eq(proxyAccount.getDomainUrl() + ".well-known/jwks.json"),
            com.nhaarman.mockitokotlin2.any<RequestOptions>()
        )

        // 5. resume, perform the code exchange, and make assertions
        Assert.assertTrue(resume(intent))
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasCredentials())
        val codeOptionsCaptor = argumentCaptor<RequestOptions>()
        verify(networkingClient).load(
            com.nhaarman.mockitokotlin2.eq("https://test.domain.com/oauth/token"),
            codeOptionsCaptor.capture()
        )
        MatcherAssert.assertThat(
            codeOptionsCaptor.firstValue,
            Matchers.`is`(Matchers.notNullValue())
        )
        MatcherAssert.assertThat(
            codeOptionsCaptor.firstValue.method, Matchers.`is`(
                Matchers.instanceOf(
                    POST::class.java
                )
            )
        )
        MatcherAssert.assertThat<Map<String, String>>(
            codeOptionsCaptor.firstValue.parameters,
            IsMapContaining.hasEntry("code", "1234")
        )
        MatcherAssert.assertThat<Map<String, String>>(
            codeOptionsCaptor.firstValue.parameters,
            IsMapContaining.hasEntry("grant_type", "authorization_code")
        )
        MatcherAssert.assertThat<Map<String, String>>(
            codeOptionsCaptor.firstValue.parameters,
            IsMapContaining.hasKey("code_verifier")
        )
        MatcherAssert.assertThat<Map<String, String>>(
            codeOptionsCaptor.firstValue.headers, Matchers.`is`(
                IsMapContaining.hasKey("Auth0-Client")
            )
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginWithRequestCodeWithCodeGrant() {
        val expiresAt = Date()
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        MatcherAssert.assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        MatcherAssert.assertThat(
            sentNonce,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["nonce"] = sentNonce
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val intent = createAuthIntent(
            createHash(
                expectedIdToken,
                null,
                null,
                null,
                null,
                sentState,
                null,
                null,
                "1234"
            )
        )
        val codeCredentials = Credentials(
            expectedIdToken,
            "codeAccess",
            "codeType",
            "codeRefresh",
            expiresAt,
            "codeScope"
        )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(ArgumentMatchers.eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasCredentials())
        val credentials = authCallback.credentials
        MatcherAssert.assertThat(credentials, `is`(notNullValue()))
        MatcherAssert.assertThat(credentials.idToken, `is`(expectedIdToken))
        MatcherAssert.assertThat(credentials.accessToken, `is`("codeAccess"))
        MatcherAssert.assertThat(credentials.refreshToken, `is`("codeRefresh"))
        MatcherAssert.assertThat(credentials.type, `is`("codeType"))
        MatcherAssert.assertThat(credentials.expiresAt, `is`(expiresAt))
        MatcherAssert.assertThat(credentials.scope, `is`("codeScope"))
        mockAPI.shutdown()
    }

    @Test
    public fun shouldResumeLoginWithRequestCodeWhenResultCancelled() {
        login(account)
            .start(activity, callback)
        val intent = createAuthIntent(null)
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("a0.authentication_canceled")
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("The user closed the browser app and the authentication was canceled.")
        )
    }

    @Test
    public fun shouldReThrowAnyFailedCodeExchangeDialogOnLogin() {
        val dialog = Mockito.mock(Dialog::class.java)
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onFailure(dialog)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        login(account)
            .withState("1234567890")
            .withPKCE(pkce)
            .start(activity, callback)
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                1111L,
                "1234567890",
                null,
                null,
                "1234"
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(dialog)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReThrowAnyFailedCodeExchangeExceptionOnLoginWithCodeGrant() {
        val exception = Mockito.mock(
            AuthenticationException::class.java
        )
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onFailure(exception)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        login(account)
            .withState("1234567890")
            .withNonce(JwtTestUtils.EXPECTED_NONCE)
            .withPKCE(pkce)
            .start(activity, callback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["iss"] = account.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val intent = createAuthIntent(
            createHash(
                expectedIdToken,
                null,
                null,
                null,
                null,
                "1234567890",
                null,
                null,
                "1234"
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(exception)
    }

    @Test
    public fun shouldFailToResumeLoginWithIntentWithAccessDenied() {
        login(account)
            .withState("1234567890")
            .start(activity, callback)
        val intent = createAuthIntent(
            createHash(
                null,
                "aToken",
                null,
                "urlType",
                1111L,
                "1234567890",
                "access_denied",
                null,
                null
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        MatcherAssert.assertThat(authExceptionCaptor.firstValue.getCode(), `is`("access_denied"))
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("Permissions were not granted. Try again.")
        )
    }

    @Test
    public fun shouldFailToResumeLoginWithIntentWithRuleError() {
        login(account)
            .withState("1234567890")
            .start(activity, callback)
        val intent = createAuthIntent(
            createHash(
                null,
                "aToken",
                null,
                "urlType",
                1111L,
                "1234567890",
                "unauthorized",
                "Custom Rule Error",
                null
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        MatcherAssert.assertThat(authExceptionCaptor.firstValue.getCode(), `is`("unauthorized"))
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("Custom Rule Error")
        )
    }

    @Test
    public fun shouldFailToResumeLoginWithIntentWithConfigurationInvalid() {
        login(account)
            .withState("1234567890")
            .start(activity, callback)
        val intent = createAuthIntent(
            createHash(
                null,
                "aToken",
                null,
                "urlType",
                1111L,
                "1234567890",
                "some other error",
                null,
                null
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("a0.invalid_configuration")
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("The application isn't configured properly for the social connection. Please check your Auth0's application configuration")
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWhenRSAKeyIsMissingFromJWKSet() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnEmptyJsonWebKeys()
        val authCallback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withState("1234567890")
            .withNonce(JwtTestUtils.EXPECTED_NONCE)
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                "1234567890",
                null,
                null,
                "1234"
            )
        )
        val codeCredentials =
            Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasError())
        val error = authCallback.error
        MatcherAssert.assertThat(error, `is`(notNullValue()))
        MatcherAssert.assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        MatcherAssert.assertThat(
            error.cause?.message,
            `is`("Could not find a public key for kid \"key123\"")
        )
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWhenJWKSRequestFails() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnInvalidRequest()
        val authCallback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withState("1234567890")
            .withNonce(JwtTestUtils.EXPECTED_NONCE)
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                "1234567890",
                null,
                null,
                "1234"
            )
        )
        val codeCredentials =
            Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasError())
        val error = authCallback.error
        MatcherAssert.assertThat(error, `is`(notNullValue()))
        MatcherAssert.assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        MatcherAssert.assertThat(
            error.cause?.message,
            `is`("Could not find a public key for kid \"key123\"")
        )
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWhenKeyIdIsMissingFromIdTokenHeader() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withState("1234567890")
            .withNonce("abcdefg")
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        val expectedIdToken =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHwxMjM0NTY3ODkifQ.PZivSuGSAWpSU62-iHwI16Po9DgO9lN7SLB3168P03wXBkue6nxbL3beq6jjW9uuhqRKfOiDtsvtr3paGXHONarPqQ1LEm4TDg8CM6AugaphH36EjEjL0zEYo0nxz9Fv1Xu9_bWSzfmLLgRefjZ5R0muV7JlyfBgtkfG0avD3PtjlNtToXX1sN9DyhgCT-STX9kSQAlk23V1XA3c8st09QgmQRgtZC3ZmTEHqq_FTmFUkVUNM6E0LbgLR7bLcOx4Xqayp1mqZxUgTg7ynHI6Ey4No-R5_twAki_BR8uG0TxqHlPxuU9QTzEvCQxrqzZZufRv_kIn2-fqrF3yr3z4Og"
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                "1234567890",
                null,
                null,
                "1234"
            )
        )
        val codeCredentials =
            Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasError())
        val error = authCallback.error
        MatcherAssert.assertThat(error, `is`(notNullValue()))
        MatcherAssert.assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        MatcherAssert.assertThat(
            error.cause?.message,
            `is`("Could not find a public key for kid \"null\"")
        )
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginWhenJWKSRequestSuceeds() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withState("1234567890")
            .withNonce(JwtTestUtils.EXPECTED_NONCE)
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                "1234567890",
                null,
                null,
                "1234"
            )
        )
        val codeCredentials =
            Credentials(expectedIdToken, "aToken", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasCredentials())
        val credentials = authCallback.credentials
        MatcherAssert.assertThat(credentials.accessToken, `is`("aToken"))
        MatcherAssert.assertThat(credentials.idToken, `is`(expectedIdToken))
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginIgnoringEmptyCustomIDTokenVerificationIssuer() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        // if specifying a null issuer for token verification, should use the domain URL of the account
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        val authCallback = MockAuthCallback()
        login(proxyAccount)
            .withIdTokenVerificationIssuer("")
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        MatcherAssert.assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        MatcherAssert.assertThat(
            sentNonce,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["nonce"] = sentNonce
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                sentState,
                null,
                null,
                "1234"
            )
        )
        val codeCredentials =
            Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasCredentials())
        val credentials = authCallback.credentials
        MatcherAssert.assertThat(credentials, `is`(notNullValue()))
        MatcherAssert.assertThat(credentials.idToken, `is`(expectedIdToken))
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginUsingCustomIDTokenVerificationIssuer() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withIdTokenVerificationIssuer("https://some.different.issuer/")
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        MatcherAssert.assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        MatcherAssert.assertThat(
            sentNonce,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["nonce"] = sentNonce
        jwtBody["iss"] = "https://some.different.issuer/"
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                sentState,
                null,
                null,
                "1234"
            )
        )
        val codeCredentials =
            Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasCredentials())
        val credentials = authCallback.credentials
        MatcherAssert.assertThat(credentials, `is`(notNullValue()))
        MatcherAssert.assertThat(credentials.idToken, `is`(expectedIdToken))
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWithHS256IdTokenAndOIDCConformantConfiguration() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        val authCallback = MockAuthCallback()
        login(proxyAccount)
            .withState("1234567890")
            .withNonce(JwtTestUtils.EXPECTED_NONCE)
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("HS256", jwtBody)
        val codeCredentials =
            Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                "1234567890",
                null,
                null,
                "1234"
            )
        )
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasError())
        val error = authCallback.error
        MatcherAssert.assertThat(error, `is`(notNullValue()))
        MatcherAssert.assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        MatcherAssert.assertThat(
            error.cause?.message,
            `is`("Signature algorithm of \"HS256\" is not supported. Expected the ID token to be signed with RS256.")
        )
        mockAPI.shutdown()
    }

    @Test
    public fun shouldFailToResumeLoginWithIntentWithLoginRequired() {
        login(account)
            .withState("1234567890")
            .start(activity, callback)
        val intent = createAuthIntent(
            createHash(
                null,
                "aToken",
                null,
                "urlType",
                1111L,
                "1234567890",
                "login_required",
                "Login Required",
                null
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("login_required")
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("Login Required")
        )
    }

    @Test
    public fun shouldFailToResumeLoginWithRequestCodeWithLoginRequired() {
        login(account)
            .withState("1234567890")
            .start(activity, callback)
        val intent = createAuthIntent(
            createHash(
                null,
                "aToken",
                null,
                "urlType",
                1111L,
                "1234567890",
                "login_required",
                "Login Required",
                null
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("login_required")
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("Login Required")
        )
    }

    @Test
    public fun shouldFailToResumeLoginWithIntentWithInvalidState() {
        login(account)
            .withState("abcdefghijk")
            .start(activity, callback)
        val intent = createAuthIntent(
            createHash(
                null,
                "aToken",
                null,
                "urlType",
                1111L,
                "1234567890",
                null,
                null,
                null
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        MatcherAssert.assertThat(authExceptionCaptor.firstValue.getCode(), `is`("access_denied"))
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("The received state is invalid. Try again.")
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWithIntentWithInvalidMaxAge() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withState("state")
            .withNonce(JwtTestUtils.EXPECTED_NONCE)
            .withIdTokenVerificationLeeway(0)
            .withMaxAge(5) //5 secs
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        val originalClock = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS / 1000
        val authTime = originalClock + 1
        val expiredMaxAge = originalClock + 10
        managerInstance.currentTimeInMillis = expiredMaxAge * 1000
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["auth_time"] = authTime
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val intent = createAuthIntent(
            createHash(
                expectedIdToken,
                null,
                null,
                null,
                null,
                "state",
                null,
                null,
                "1234"
            )
        )
        val codeCredentials =
            Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasError())
        val error = authCallback.error
        MatcherAssert.assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        MatcherAssert.assertThat(
            error.cause?.message,
            `is`("Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (1567314010) is after last auth at (1567314006)")
        )
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWithIntentWithInvalidNonce() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withState("state")
            .withNonce("0987654321")
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("RS256", jwtBody)
        val intent =
            createAuthIntent(createHash(null, null, null, null, null, "state", null, null, "1234"))
        val codeCredentials =
            Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(authCallback, AuthCallbackMatcher.hasError())
        val error = authCallback.error
        MatcherAssert.assertThat(error, `is`(notNullValue()))
        MatcherAssert.assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        MatcherAssert.assertThat(
            error.cause?.message,
            `is`("Nonce (nonce) claim mismatch in the ID token; expected \"0987654321\", found \"" + JwtTestUtils.EXPECTED_NONCE + "\"")
        )
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWithNotSupportedSigningAlgorithm() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPI()
        mockAPI.willReturnValidJsonWebKeys()
        val callback = MockAuthCallback()
        val proxyAccount: Auth0 = MockAuth0(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        login(proxyAccount)
            .withState("state")
            .withNonce(JwtTestUtils.EXPECTED_NONCE)
            .withPKCE(pkce)
            .start(activity, callback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("none", jwtBody)
        val intent =
            createAuthIntent(createHash(null, null, null, null, null, "state", null, null, "1234"))
        val codeCredentials =
            Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", null, "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        ShadowLooper.idleMainLooper()
        MatcherAssert.assertThat(callback, AuthCallbackMatcher.hasError())
        val error = callback.error
        MatcherAssert.assertThat(error, `is`(notNullValue()))
        MatcherAssert.assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        MatcherAssert.assertThat(
            error.cause?.message,
            `is`("Signature algorithm of \"none\" is not supported. Expected the ID token to be signed with RS256.")
        )
        mockAPI.shutdown()
    }

    @Test
    public fun shouldFailToResumeLoginWithIntentWithEmptyUriValues() {
        Mockito.verifyNoMoreInteractions(callback)
        login(account)
            .withState("abcdefghijk")
            .start(activity, callback)
        val intent = createAuthIntent("")
        Assert.assertFalse(resume(intent))
    }

    @Test
    public fun shouldFailToResumeLoginWithIntentWithoutFirstInitProvider() {
        WebAuthProvider.resetManagerInstance()
        val intent = createAuthIntent("")
        Assert.assertFalse(resume(intent))
    }

    @Test
    public fun shouldResumeLoginWithIntentWithNullIntent() {
        login(account)
            .withState("abcdefghijk")
            .start(activity, callback)
        Assert.assertFalse(resume(null))
    }

    @Test
    public fun shouldClearInstanceAfterSuccessLoginWithIntent() {
        login(account)
            .start(activity, callback)
        assertThat(
            WebAuthProvider.managerInstance,
            `is`(notNullValue())
        )
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                "1234567890",
                null,
                null,
                null
            )
        )
        Assert.assertTrue(resume(intent))
        assertThat(
            WebAuthProvider.managerInstance,
            `is`(CoreMatchers.nullValue())
        )
    }

    @Test
    public fun shouldClearInstanceAfterSuccessLoginWithRequestCode() {
        login(account)
            .start(activity, callback)
        assertThat(
            WebAuthProvider.managerInstance,
            `is`(notNullValue())
        )
        val intent = createAuthIntent(
            createHash(
                null,
                null,
                null,
                null,
                null,
                "1234567890",
                null,
                null,
                null
            )
        )
        Assert.assertTrue(resume(intent))
        assertThat(
            WebAuthProvider.managerInstance,
            `is`(CoreMatchers.nullValue())
        )
    }

    @Test
    public fun shouldFailToStartLoginWithBrowserWhenNoCompatibleBrowserAppIsInstalled() {
        val noBrowserOptions = Mockito.mock(
            CustomTabsOptions::class.java
        )
        Mockito.`when`(noBrowserOptions.hasCompatibleBrowser(activity.packageManager))
            .thenReturn(false)
        login(account)
            .withCustomTabsOptions(noBrowserOptions)
            .start(activity, callback)
        verify(callback).onFailure(authExceptionCaptor.capture())
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("a0.browser_not_available")
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("No compatible Browser application is installed.")
        )
        assertThat(
            WebAuthProvider.managerInstance,
            `is`(CoreMatchers.nullValue())
        )
    }

    @Test
    public fun shouldNotFailToStartLoginWithWebviewWhenNoBrowserAppIsInstalled() {
        val noBrowserOptions = Mockito.mock(
            CustomTabsOptions::class.java
        )
        Mockito.`when`(noBrowserOptions.hasCompatibleBrowser(activity.packageManager))
            .thenReturn(false)
        login(account)
            .start(activity, callback)
        verify(activity).startActivityForResult(
            intentCaptor.capture(), ArgumentMatchers.anyInt()
        )
        val intent = intentCaptor.firstValue
        MatcherAssert.assertThat(intent, `is`(notNullValue()))
        MatcherAssert.assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        MatcherAssert.assertThat(intent, IntentMatchers.hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        MatcherAssert.assertThat(intent.data, `is`(CoreMatchers.nullValue()))
        verify(callback, Mockito.never()).onFailure(
            com.nhaarman.mockitokotlin2.any<AuthenticationException>()
        )
    }

    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//
    //** LOG OUT FEATURE **//
    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//
    @Test
    public fun shouldInitLogoutWithAccount() {
        logout(account)
            .start(activity, voidCallback)
        Assert.assertNotNull(WebAuthProvider.managerInstance)
    }

    //scheme
    @Test
    public fun shouldHaveDefaultSchemeOnLogout() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithName("returnTo"))
        val returnToUri = Uri.parse(uri?.getQueryParameter("returnTo"))
        MatcherAssert.assertThat(returnToUri, UriMatchers.hasScheme("https"))
    }

    @Test
    public fun shouldSetSchemeOnLogout() {
        logout(account)
            .withScheme("myapp")
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(uri, UriMatchers.hasParamWithName("returnTo"))
        val returnToUri = Uri.parse(uri?.getQueryParameter("returnTo"))
        MatcherAssert.assertThat(returnToUri, UriMatchers.hasScheme("myapp"))
    }

    // client id
    @Test
    public fun shouldAlwaysSetClientIdOnLogout() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri,
            UriMatchers.hasParamWithValue("client_id", JwtTestUtils.EXPECTED_AUDIENCE)
        )
    }

    // auth0 related
    @Test
    public fun shouldHaveTelemetryInfoOnLogout() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri, UriMatchers.hasParamWithValue(
                `is`("auth0Client"), not(
                    Matchers.isEmptyOrNullString()
                )
            )
        )
    }

    @Test
    public fun shouldHaveReturnToUriOnLogout() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri?.getQueryParameter("returnTo"),
            `is`("https://test.domain.com/android/com.auth0.android.auth0.test/callback")
        )
    }

    @Test
    public fun shouldSetReturnToUrlIgnoringSchemeOnLogout() {
        logout(account)
            .withScheme("https")
            .withReturnToUrl("myapp://app.company.com/mobile/callback")
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        MatcherAssert.assertThat(
            uri?.getQueryParameter("returnTo"),
            `is`("myapp://app.company.com/mobile/callback")
        )
    }

    // Launch log out
    @Test
    public fun shouldStartLogout() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val intent = intentCaptor.firstValue
        MatcherAssert.assertThat(intent, `is`(notNullValue()))
        MatcherAssert.assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        MatcherAssert.assertThat(intent, IntentMatchers.hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        MatcherAssert.assertThat(intent.data, `is`(CoreMatchers.nullValue()))
        val extras = intentCaptor.firstValue.extras
        MatcherAssert.assertThat<Any?>(
            extras?.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), `is`(
                notNullValue()
            )
        )
        MatcherAssert.assertThat(
            extras?.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS),
            `is`(true)
        )
        MatcherAssert.assertThat<Any?>(
            extras?.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS), `is`(
                notNullValue()
            )
        )
    }

    @Test
    public fun shouldStartLogoutWithCustomTabsOptions() {
        val options = CustomTabsOptions.newBuilder().build()
        logout(account)
            .withCustomTabsOptions(options)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val intent = intentCaptor.firstValue
        MatcherAssert.assertThat(intent, `is`(notNullValue()))
        MatcherAssert.assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        MatcherAssert.assertThat(intent, IntentMatchers.hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        MatcherAssert.assertThat(intent.data, `is`(CoreMatchers.nullValue()))
        val extras = intentCaptor.firstValue.extras
        MatcherAssert.assertThat<Any?>(
            extras?.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), `is`(
                notNullValue()
            )
        )
        MatcherAssert.assertThat(
            extras?.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS),
            `is`(true)
        )
        MatcherAssert.assertThat(
            extras?.getParcelable<Parcelable>(AuthenticationActivity.EXTRA_CT_OPTIONS) as CustomTabsOptions?,
            `is`(options)
        )
    }

    @Test
    public fun shouldFailToStartLogoutWhenNoCompatibleBrowserAppIsInstalled() {
        val noBrowserOptions = Mockito.mock(
            CustomTabsOptions::class.java
        )
        Mockito.`when`(noBrowserOptions.hasCompatibleBrowser(activity.packageManager))
            .thenReturn(false)
        logout(account)
            .withCustomTabsOptions(noBrowserOptions)
            .start(activity, voidCallback)
        verify(voidCallback).onFailure(authExceptionCaptor.capture())
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("a0.browser_not_available")
        )
        MatcherAssert.assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("No compatible Browser application is installed.")
        )
        assertThat(
            WebAuthProvider.managerInstance,
            `is`(CoreMatchers.nullValue())
        )
    }

    @Test
    public fun shouldResumeLogoutSuccessfullyWithIntent() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))
        val intent = createAuthIntent("")
        Assert.assertTrue(resume(intent))
        verify(voidCallback).onSuccess(eq<Unit?>(null))
    }

    @Test
    public fun shouldResumeLogoutFailingWithIntent() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        MatcherAssert.assertThat(uri, `is`(notNullValue()))

        //null data translates to result canceled
        val intent = createAuthIntent(null)
        Assert.assertTrue(resume(intent))
        verify(voidCallback).onFailure(auth0ExceptionCaptor.capture())
        MatcherAssert.assertThat(
            auth0ExceptionCaptor.firstValue,
            `is`(notNullValue())
        )
        MatcherAssert.assertThat(
            auth0ExceptionCaptor.firstValue.message,
            `is`("The user closed the browser app so the logout was cancelled.")
        )
        assertThat(
            WebAuthProvider.managerInstance,
            `is`(CoreMatchers.nullValue())
        )
    }

    @Test
    public fun shouldClearLogoutManagerInstanceAfterSuccessfulLogout() {
        logout(account)
            .start(activity, voidCallback)
        assertThat(
            WebAuthProvider.managerInstance,
            `is`(notNullValue())
        )
        val intent = createAuthIntent("")
        Assert.assertTrue(resume(intent))
        assertThat(
            WebAuthProvider.managerInstance,
            `is`(CoreMatchers.nullValue())
        )
    }

    //**  ** ** ** ** **  **//
    //**  ** ** ** ** **  **//
    //** Helpers Functions**//
    //**  ** ** ** ** **  **//
    //**  ** ** ** ** **  **//
    private fun createAuthIntent(hash: String?): Intent {
        val intent = Intent()
        if (hash == null) {
            return intent
        }
        val validUri = Uri.parse("https://domain.auth0.com/android/package/callback$hash")
        intent.data = validUri
        return intent
    }

    private fun createHash(
        idToken: String?,
        accessToken: String?,
        refreshToken: String?,
        tokenType: String?,
        expiresIn: Long?,
        state: String?,
        error: String?,
        errorDescription: String?,
        pkceCode: String?
    ): String {
        var hash = "#"
        if (accessToken != null) {
            hash = hash + "access_token=" + accessToken + "&"
        }
        if (idToken != null) {
            hash = hash + "id_token=" + idToken + "&"
        }
        if (refreshToken != null) {
            hash = hash + "refresh_token=" + refreshToken + "&"
        }
        if (tokenType != null) {
            hash = hash + "token_type=" + tokenType + "&"
        }
        if (expiresIn != null) {
            hash = hash + "expires_in=" + expiresIn.toString() + "&"
        }
        if (state != null) {
            hash = hash + "state=" + state + "&"
        }
        if (error != null) {
            hash = hash + "error=" + error + "&"
        }
        if (errorDescription != null) {
            hash = hash + "error_description=" + errorDescription + "&"
        }
        if (pkceCode != null) {
            hash = hash + "code=" + pkceCode + "&"
        }
        if (hash.endsWith("&")) {
            hash = hash.substring(0, hash.length - 1)
        }
        return if (hash.length == 1) "" else hash
    }

    private companion object {
        private const val KEY_STATE = "state"
        private const val KEY_NONCE = "nonce"
    }
}