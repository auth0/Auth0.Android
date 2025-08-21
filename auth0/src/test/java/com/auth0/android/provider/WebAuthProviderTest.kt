package com.auth0.android.provider

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Parcelable
import androidx.test.espresso.intent.matcher.IntentMatchers
import androidx.test.espresso.intent.matcher.UriMatchers
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.dpop.DPoPException
import com.auth0.android.dpop.DPoPKeyStore
import com.auth0.android.dpop.DPoPUtil
import com.auth0.android.dpop.FakeECPrivateKey
import com.auth0.android.dpop.FakeECPublicKey
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
import com.auth0.android.util.AuthenticationAPIMockServer
import com.auth0.android.util.SSLTestUtils
import com.nhaarman.mockitokotlin2.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.hamcrest.CoreMatchers
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.instanceOf
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
import org.mockito.ArgumentMatchers
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.`when`
import org.mockito.MockitoAnnotations
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
    private lateinit var callback: Callback<Credentials, AuthenticationException>

    @Mock
    private lateinit var voidCallback: Callback<Void?, AuthenticationException>
    private lateinit var activity: Activity
    private lateinit var account: Auth0
    private lateinit var mockKeyStore: DPoPKeyStore
    private lateinit var mockContext: Context

    private val authExceptionCaptor: KArgumentCaptor<AuthenticationException> = argumentCaptor()
    private val intentCaptor: KArgumentCaptor<Intent> = argumentCaptor()
    private val credentialsCaptor: KArgumentCaptor<Credentials> = argumentCaptor()
    private val callbackCaptor: KArgumentCaptor<Callback<Credentials, AuthenticationException>> =
        argumentCaptor()

    private val customAuthorizeUrl = "https://custom.domain.com/custom_auth"
    private val customLogoutUrl = "https://custom.domain.com/custom_logout"

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        activity = Mockito.spy(Robolectric.buildActivity(Activity::class.java).get())
        account =
            Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, JwtTestUtils.EXPECTED_BASE_DOMAIN)
        account.networkingClient = SSLTestUtils.testClient

        mockKeyStore = mock()
        mockContext = mock()

        DPoPUtil.keyStore = mockKeyStore

        //Next line is needed to avoid CustomTabService from being bound to Test environment
        Mockito.doReturn(false).`when`(activity).bindService(
            any(),
            any(),
            ArgumentMatchers.anyInt()
        )
        BrowserPickerTest.setupBrowserContext(
            activity,
            listOf("com.auth0.browser"),
            null,
            null
        )

        `when`(mockKeyStore.hasKeyPair()).thenReturn(false)
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

    @Test
    public fun shouldSetCustomAuthorizeUrlOnLogin() {
        login(account)
            .withAuthorizeUrl(customAuthorizeUrl)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri?.scheme, `is`("https"))
        assertThat(uri?.host, `is`("custom.domain.com"))
        assertThat(uri?.path, `is`("/custom_auth"))
        assertThat(uri, UriMatchers.hasParamWithName("client_id"))
        assertThat(uri, UriMatchers.hasParamWithName("redirect_uri"))
        assertThat(uri, UriMatchers.hasParamWithName("response_type"))
        assertThat(uri, UriMatchers.hasParamWithName("state"))
    }

    //scheme
    @Test
    public fun shouldHaveDefaultSchemeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithName("redirect_uri"))
        val redirectUri = Uri.parse(uri?.getQueryParameter("redirect_uri"))
        assertThat(redirectUri, UriMatchers.hasScheme("https"))
    }

    @Test
    public fun shouldSetSchemeOnLogin() {
        login(account)
            .withScheme("myapp")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithName("redirect_uri"))
        val redirectUri = Uri.parse(uri?.getQueryParameter("redirect_uri"))
        assertThat(redirectUri, UriMatchers.hasScheme("myapp"))
    }

    //connection
    @Test
    public fun shouldNotHaveDefaultConnectionOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, not(UriMatchers.hasParamWithName("connection")))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("connection", "my-connection"))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("connection", "my-connection"))
    }

    @Test
    public fun shouldSetConnectionOnLogin() {
        login(account)
            .withConnection("some-connection")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, not(UriMatchers.hasParamWithName("audience")))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
            uri,
            UriMatchers.hasParamWithValue("audience", "https://google.com/apis")
        )
    }


    @Test
    public fun enablingDPoPWillGenerateNewKeyPairIfOneDoesNotExist() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(false)
        WebAuthProvider.useDPoP(mockContext)
            .login(account)
            .start(activity, callback)
        verify(mockKeyStore).generateKeyPair(any(), any())
    }

    @Test
    public fun shouldNotHaveDpopJwkOnLoginIfDPoPIsDisabled() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(
            uri,
            not(
                UriMatchers.hasParamWithName("dpop_jkt")
            )
        )
    }

    @Test
    public fun shouldHaveDpopJwkOnLoginIfDPoPIsEnabled() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(true)
        `when`(mockKeyStore.getKeyPair()).thenReturn(Pair(mock(), FakeECPublicKey()))

        WebAuthProvider.useDPoP(mockContext)
            .login(account)
            .start(activity, callback)

        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(
            uri,
            UriMatchers.hasParamWithValue("dpop_jkt", "KQ-r0YQMCm0yVnGippcsZK4zO7oGIjOkNRbvILjjBAo")
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
            uri,
            UriMatchers.hasParamWithValue("scope", "openid profile email")
        )
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
            uri,
            UriMatchers.hasParamWithValue("scope", "profile super_scope openid")
        )
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
            uri,
            UriMatchers.hasParamWithValue("scope", "profile super_scope openid")
        )
    }

    //connection scope
    @Test
    public fun shouldNotHaveDefaultConnectionScopeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("state", "1234567890"))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("state", "abcdefg"))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("state", "1234567890"))
    }

    @Test
    public fun shouldSetStateOnLogin() {
        login(account)
            .withState("abcdefg")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("state", "abcdefg"))
    }

    //nonce
    @Test
    public fun shouldSetNonceByDefaultIfResponseTypeIncludesCodeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithName("nonce"))
    }

    @Test
    public fun shouldSetNonNullNonceOnLogin() {
        login(account)
            .withNonce("")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("nonce", "1234567890"))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("nonce", "1234567890"))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("nonce", "abcdefg"))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("nonce", "1234567890"))
    }

    @Test
    public fun shouldSetNonceOnLogin() {
        login(account)
            .withNonce("abcdefg")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("nonce", "abcdefg"))
    }

    @Test
    public fun shouldGenerateRandomStringIfDefaultValueIsMissingOnLogin() {
        login(account)
            .start(activity, callback)
        val random1 = OAuthManager.getRandomString(null)
        val random2 = OAuthManager.getRandomString(null)
        assertThat(random1, `is`(notNullValue()))
        assertThat(random2, `is`(notNullValue()))
        assertThat(
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
        assertThat(random1, `is`("some"))
        assertThat(random2, `is`("some"))
    }

    // organizations

    @Test
    public fun shouldNotSetOrganizationByDefaultOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, not(UriMatchers.hasParamWithName("organization")))
    }

    @Test
    public fun shouldNotSetInvitationByDefaultOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, not(UriMatchers.hasParamWithName("invitation")))
    }

    @Test
    public fun shouldSetOrganizationOnLogin() {
        login(account)
            .withOrganization("travel0")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("organization", "travel0"))
    }

    @Test
    public fun shouldSetOrganizationAndInvitationFromInvitationUrl() {
        login(account)
            .withInvitationUrl("https://tenant.auth0.com/login?organization=travel0&invitation=inv123")
            .withOrganization("layer0") // this line will be ignored
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("organization", "travel0"))
        assertThat(uri, UriMatchers.hasParamWithValue("invitation", "inv123"))
    }

    @Test
    public fun shouldFailWhenInvitationUrlDoesNotContainOrganization() {
        login(account)
            .withInvitationUrl("https://tenant.auth0.com/login?invitation=inv123")
            .start(activity, callback)

        verify(callback).onFailure(authExceptionCaptor.capture())
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(authExceptionCaptor.firstValue.getCode(), `is`("a0.invalid_invitation_url"))
        assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("The invitation URL provided doesn't contain the 'organization' or 'invitation' values.")
        )
    }

    @Test
    public fun shouldFailWhenInvitationUrlDoesNotContainInvitation() {
        login(account)
            .withInvitationUrl("https://tenant.auth0.com/login?organization=travel0")
            .start(activity, callback)

        verify(callback).onFailure(authExceptionCaptor.capture())
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(authExceptionCaptor.firstValue.getCode(), `is`("a0.invalid_invitation_url"))
        assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("The invitation URL provided doesn't contain the 'organization' or 'invitation' values.")
        )
    }

    // max_age
    @Test
    public fun shouldNotSetMaxAgeByDefaultOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, not(UriMatchers.hasParamWithName("max_age")))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("max_age", "09876"))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("max_age", "12345"))
    }

    // auth0 related
    @Test
    public fun shouldHaveClientIdOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("response_type", "code"))
    }

    @Test
    public fun shouldSetResponseTypeCodeOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("response_type", "code"))
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("a", "valid"))
        assertThat(uri, not(UriMatchers.hasParamWithName("b")))
    }

    @Test
    public fun shouldBuildAuthorizeURIWithoutNullsOnLogin() {
        login(account)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        val params = uri!!.queryParameterNames
        for (name in params) {
            assertThat(
                uri,
                not(UriMatchers.hasParamWithValue(name, null))
            )
            assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasScheme(baseUriString.scheme))
        assertThat(uri, UriMatchers.hasHost(baseUriString.host))
        assertThat(uri, UriMatchers.hasPath(baseUriString.path))
    }

    @Test
    public fun shouldBuildAuthorizeURIWithResponseTypeCodeOnLogin() {
        login(account)
            .withState("a-state")
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithName("nonce"))
        assertThat(
            uri, UriMatchers.hasParamWithValue(
                `is`("code_challenge"), not(
                    Matchers.isEmptyOrNullString()
                )
            )
        )
        assertThat(
            uri,
            UriMatchers.hasParamWithValue("code_challenge_method", "S256")
        )
        assertThat(uri, UriMatchers.hasParamWithValue("response_type", "code"))
    }

    @Test
    public fun shouldStartLoginWithBrowserCustomTabsOptions() {
        val options: CustomTabsOptions = CustomTabsOptions.newBuilder().build()
        login(account)
            .withCustomTabsOptions(options)
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val intent = intentCaptor.firstValue
        assertThat(intent, `is`(notNullValue()))
        assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        assertThat(intent, IntentMatchers.hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        assertThat(intent.data, `is`(CoreMatchers.nullValue()))
        val extras = intentCaptor.firstValue.extras
        assertThat(
            extras?.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), `is`(
                notNullValue()
            )
        )
        assertThat(
            extras?.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS),
            `is`(true)
        )
        assertThat(
            extras?.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS) as? CustomTabsOptions,
            `is`(options)
        )
    }

    @Test
    public fun shouldStartLoginWithEphemeralSession() {
        login(account)
            .enableEphemeralSession()
            .start(activity, callback)
        verify(activity).startActivity(intentCaptor.capture())
        val intent = intentCaptor.firstValue
        assertThat(intent, `is`(notNullValue()))
        assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        val extras = intentCaptor.firstValue.extras
        assertThat(
            extras?.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS),
            `is`(true)
        )
        val customTabsOptions = extras?.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS) as? CustomTabsOptions
        assertThat(customTabsOptions, `is`(notNullValue()))
        
        // Verify that ephemeral browsing is enabled by checking the intent that would be generated
        val context = activity as Context
        val testIntent = customTabsOptions?.toIntent(context, null)
        assertThat(testIntent, `is`(notNullValue()))
        assertThat(testIntent?.hasExtra(androidx.browser.customtabs.CustomTabsIntent.EXTRA_EPHEMERAL_BROWSING_ENABLED), `is`(true))
        assertThat(testIntent?.getBooleanExtra(androidx.browser.customtabs.CustomTabsIntent.EXTRA_EPHEMERAL_BROWSING_ENABLED, false), `is`(true))
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
        Assert.assertTrue(resume(intent))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginWithIntentWithCodeGrant() {
        val expiresAt = Date()
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
        login(proxyAccount)
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        assertThat(
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
        verify(authCallback).onSuccess(credentialsCaptor.capture())
        val credentials = credentialsCaptor.firstValue
        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.idToken, `is`(expectedIdToken))
        assertThat(credentials.accessToken, `is`("codeAccess"))
        assertThat(credentials.refreshToken, `is`("codeRefresh"))
        assertThat(credentials.type, `is`("codeType"))
        assertThat(credentials.expiresAt, `is`(expiresAt))
        assertThat(credentials.scope, `is`("codeScope"))
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginWithCustomNetworkingClient() {
        val networkingClient: NetworkingClient = Mockito.spy(DefaultClient())
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()

        // 1. start the webauth flow. the browser would open
        val proxyAccount =
            Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, JwtTestUtils.EXPECTED_BASE_DOMAIN)
        proxyAccount.networkingClient = networkingClient
        login(proxyAccount)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS

        // 2. capture the intent filter to obtain the state and nonce sent
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        assertThat(
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
        val jsonResponse = """
            {
                "id_token":"$expectedIdToken",
                "access_token":"accessToken",
                "token_type":"tokenType",
                "expires_in":8600
            }
        """.trimIndent()
        val codeInputStream: InputStream = ByteArrayInputStream(jsonResponse.toByteArray())
        val codeResponse = ServerResponse(200, codeInputStream, emptyMap())
        Mockito.doReturn(codeResponse).`when`(networkingClient).load(
            eq(proxyAccount.getDomainUrl() + "oauth/token"),
            any()
        )

        // 4. craft a JWKS response with expected keys
        val encoded = Files.readAllBytes(Paths.get("src/test/resources/rsa_jwks.json"))
        val jwksInputStream: InputStream = ByteArrayInputStream(encoded)
        val jwksResponse = ServerResponse(200, jwksInputStream, emptyMap())
        Mockito.doReturn(jwksResponse).`when`(networkingClient).load(
            eq(proxyAccount.getDomainUrl() + ".well-known/jwks.json"),
            any()
        )

        // 5. resume, perform the code exchange, and make assertions
        Assert.assertTrue(resume(intent))
        ShadowLooper.idleMainLooper()
        verify(authCallback).onSuccess(credentialsCaptor.capture())
        assertThat(credentialsCaptor.firstValue, `is`(notNullValue()))
        val codeOptionsCaptor = argumentCaptor<RequestOptions>()
        verify(networkingClient).load(
            eq("https://test.domain.com/oauth/token"),
            codeOptionsCaptor.capture()
        )
        assertThat(
            codeOptionsCaptor.firstValue,
            Matchers.`is`(Matchers.notNullValue())
        )
        assertThat(
            codeOptionsCaptor.firstValue.method, Matchers.`is`(
                Matchers.instanceOf(
                    POST::class.java
                )
            )
        )
        assertThat<Map<String, Any>>(
            codeOptionsCaptor.firstValue.parameters,
            IsMapContaining.hasEntry("code", "1234")
        )
        assertThat<Map<String, Any>>(
            codeOptionsCaptor.firstValue.parameters,
            IsMapContaining.hasEntry("grant_type", "authorization_code")
        )
        assertThat<Map<String, Any>>(
            codeOptionsCaptor.firstValue.parameters,
            IsMapContaining.hasKey("code_verifier")
        )
        assertThat<Map<String, String>>(
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
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
        login(proxyAccount)
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        assertThat(
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
        verify(authCallback).onSuccess(credentialsCaptor.capture())
        val credentials = credentialsCaptor.firstValue
        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.idToken, `is`(expectedIdToken))
        assertThat(credentials.accessToken, `is`("codeAccess"))
        assertThat(credentials.refreshToken, `is`("codeRefresh"))
        assertThat(credentials.type, `is`("codeType"))
        assertThat(credentials.expiresAt, `is`(expiresAt))
        assertThat(credentials.scope, `is`("codeScope"))
        mockAPI.shutdown()
    }

    @Test
    public fun shouldResumeLoginWithRequestCodeWhenResultCancelled() {
        login(account)
            .start(activity, callback)
        val intent = createAuthIntent(null)
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("a0.authentication_canceled")
        )
        assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("The user closed the browser app and the authentication was canceled.")
        )
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
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(authExceptionCaptor.firstValue.getCode(), `is`("access_denied"))
        assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("Permissions were not granted. Try again.")
        )
    }

    @Test
    public fun shouldFailToResumeLoginWithIntentWithAccessDeniedAndDescription() {
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
                "email is already associated with another account",
                null
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(authExceptionCaptor.firstValue.getCode(), `is`("access_denied"))
        assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("email is already associated with another account")
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
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(authExceptionCaptor.firstValue.getCode(), `is`("unauthorized"))
        assertThat(
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
                "a0.invalid_configuration",
                "The application isn't configured properly for the social connection. Please check your Auth0's application configuration",
                null
            )
        )
        Assert.assertTrue(resume(intent))
        verify(callback).onFailure(authExceptionCaptor.capture())
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("a0.invalid_configuration")
        )
        assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("The application isn't configured properly for the social connection. Please check your Auth0's application configuration")
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWhenRSAKeyIsMissingFromJWKSet() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnEmptyJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
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
            Credentials(
                expectedIdToken,
                "codeAccess",
                "codeType",
                "codeRefresh",
                Date(),
                "codeScope"
            )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        verify(authCallback).onFailure(authExceptionCaptor.capture())
        val error = authExceptionCaptor.firstValue
        assertThat(error, `is`(notNullValue()))
        assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        assertThat(
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
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnInvalidRequest()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
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
            Credentials(
                expectedIdToken,
                "codeAccess",
                "codeType",
                "codeRefresh",
                Date(),
                "codeScope"
            )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        verify(authCallback).onFailure(authExceptionCaptor.capture())
        val error = authExceptionCaptor.firstValue
        assertThat(error, `is`(notNullValue()))
        assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        assertThat(
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
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
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
            Credentials(
                expectedIdToken,
                "codeAccess",
                "codeType",
                "codeRefresh",
                Date(),
                "codeScope"
            )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        verify(authCallback).onFailure(authExceptionCaptor.capture())
        val error = authExceptionCaptor.firstValue
        assertThat(error, `is`(notNullValue()))
        assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        assertThat(
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
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
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
            Credentials(expectedIdToken, "aToken", "codeType", "codeRefresh", Date(), "codeScope")
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        verify(authCallback).onSuccess(credentialsCaptor.capture())
        val credentials = credentialsCaptor.firstValue
        assertThat(credentials.accessToken, `is`("aToken"))
        assertThat(credentials.idToken, `is`(expectedIdToken))
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginIgnoringEmptyCustomIDTokenVerificationIssuer() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        // if specifying a null issuer for token verification, should use the domain URL of the account
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        login(proxyAccount)
            .withIdTokenVerificationIssuer("")
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        assertThat(
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
            Credentials(
                expectedIdToken,
                "codeAccess",
                "codeType",
                "codeRefresh",
                Date(),
                "codeScope"
            )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        verify(authCallback).onSuccess(credentialsCaptor.capture())
        val credentials = credentialsCaptor.firstValue
        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.idToken, `is`(expectedIdToken))
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginUsingCustomIDTokenVerificationIssuer() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
        login(proxyAccount)
            .withIdTokenVerificationIssuer("https://some.different.issuer/")
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)
        assertThat(
            sentState,
            `is`(not(Matchers.isEmptyOrNullString()))
        )
        assertThat(
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
            Credentials(
                expectedIdToken,
                "codeAccess",
                "codeType",
                "codeRefresh",
                Date(),
                "codeScope"
            )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        verify(authCallback).onSuccess(credentialsCaptor.capture())
        val credentials = credentialsCaptor.firstValue
        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.idToken, `is`(expectedIdToken))
        mockAPI.shutdown()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWithHS256IdTokenAndOIDCConformantConfiguration() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
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
            Credentials(
                expectedIdToken,
                "codeAccess",
                "codeType",
                "codeRefresh",
                Date(),
                "codeScope"
            )
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
        verify(authCallback).onFailure(authExceptionCaptor.capture())
        val error = authExceptionCaptor.firstValue
        assertThat(error, `is`(notNullValue()))
        assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        assertThat(
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
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("login_required")
        )
        assertThat(
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
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("login_required")
        )
        assertThat(
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
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(authExceptionCaptor.firstValue.getCode(), `is`("access_denied"))
        assertThat(
            authExceptionCaptor.firstValue.getDescription(),
            `is`("The received state is invalid. Try again.")
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailToResumeLoginWithIntentWithInvalidMaxAge() {
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
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
            Credentials(
                expectedIdToken,
                "codeAccess",
                "codeType",
                "codeRefresh",
                Date(),
                "codeScope"
            )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        verify(authCallback).onFailure(authExceptionCaptor.capture())
        val error = authExceptionCaptor.firstValue
        assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        assertThat(
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
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
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
            Credentials(
                expectedIdToken,
                "codeAccess",
                "codeType",
                "codeRefresh",
                Date(),
                "codeScope"
            )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        mockAPI.takeRequest()
        ShadowLooper.idleMainLooper()
        verify(authCallback).onFailure(authExceptionCaptor.capture())
        val error = authExceptionCaptor.firstValue
        assertThat(error, `is`(notNullValue()))
        assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        assertThat(
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
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient
        login(proxyAccount)
            .withState("state")
            .withNonce(JwtTestUtils.EXPECTED_NONCE)
            .withPKCE(pkce)
            .start(activity, authCallback)
        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        val jwtBody = JwtTestUtils.createJWTBody()
        jwtBody["iss"] = proxyAccount.getDomainUrl()
        val expectedIdToken = JwtTestUtils.createTestJWT("none", jwtBody)
        val intent =
            createAuthIntent(createHash(null, null, null, null, null, "state", null, null, "1234"))
        val codeCredentials =
            Credentials(
                expectedIdToken,
                "codeAccess",
                "codeType",
                "codeRefresh",
                Date(),
                "codeScope"
            )
        Mockito.doAnswer {
            callbackCaptor.firstValue.onSuccess(codeCredentials)
            null
        }.`when`(pkce).getToken(eq("1234"), callbackCaptor.capture())
        Assert.assertTrue(resume(intent))
        ShadowLooper.idleMainLooper()
        verify(authCallback).onFailure(authExceptionCaptor.capture())
        val error = authExceptionCaptor.firstValue
        assertThat(error, `is`(notNullValue()))
        assertThat(
            error.cause, `is`(
                Matchers.instanceOf(
                    TokenValidationException::class.java
                )
            )
        )
        assertThat(
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
        `when`(noBrowserOptions.hasCompatibleBrowser(activity.packageManager))
            .thenReturn(false)
        login(account)
            .withCustomTabsOptions(noBrowserOptions)
            .start(activity, callback)
        verify(callback).onFailure(authExceptionCaptor.capture())
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("a0.browser_not_available")
        )
        assertThat(
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
        `when`(noBrowserOptions.hasCompatibleBrowser(activity.packageManager))
            .thenReturn(false)
        login(account)
            .start(activity, callback)
        verify(activity).startActivityForResult(
            intentCaptor.capture(), ArgumentMatchers.anyInt()
        )
        val intent = intentCaptor.firstValue
        assertThat(intent, `is`(notNullValue()))
        assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        assertThat(intent, IntentMatchers.hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        assertThat(intent.data, `is`(CoreMatchers.nullValue()))
        verify(callback, Mockito.never()).onFailure(
            any()
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

    @Test
    public fun shouldSetCustomLogoutUrlOnLogout() {
        logout(account)
            .withLogoutUrl(customLogoutUrl)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri?.scheme, `is`("https"))
        assertThat(uri?.host, `is`("custom.domain.com"))
        assertThat(uri?.path, `is`("/custom_logout"))
        assertThat(uri, UriMatchers.hasParamWithName("client_id"))
        assertThat(uri, UriMatchers.hasParamWithName("returnTo"))
    }

    //scheme
    @Test
    public fun shouldHaveDefaultSchemeOnLogout() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithName("returnTo"))
        val returnToUri = Uri.parse(uri?.getQueryParameter("returnTo"))
        assertThat(returnToUri, UriMatchers.hasScheme("https"))
    }

    @Test
    public fun shouldSetSchemeOnLogout() {
        logout(account)
            .withScheme("myapp")
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithName("returnTo"))
        val returnToUri = Uri.parse(uri?.getQueryParameter("returnTo"))
        assertThat(returnToUri, UriMatchers.hasScheme("myapp"))
    }

    // client id
    @Test
    public fun shouldAlwaysSetClientIdOnLogout() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(
            uri,
            UriMatchers.hasParamWithValue("client_id", JwtTestUtils.EXPECTED_AUDIENCE)
        )
    }

    // federated
    @Test
    public fun shouldNotUseFederatedByDefaultOnLogout() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(
            uri,
            not(UriMatchers.hasParamWithName("federated"))
        )
    }

    @Test
    public fun shouldUseFederatedOnLogout() {
        logout(account)
            .withFederated()
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(
            uri,
            UriMatchers.hasParamWithValue("federated", "1")
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        assertThat(
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
        assertThat(intent, `is`(notNullValue()))
        assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        assertThat(intent, IntentMatchers.hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        assertThat(intent.data, `is`(CoreMatchers.nullValue()))
        val extras = intentCaptor.firstValue.extras
        assertThat(
            extras?.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), `is`(
                notNullValue()
            )
        )
        assertThat(
            extras?.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS),
            `is`(true)
        )
        assertThat(
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
        assertThat(intent, `is`(notNullValue()))
        assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        assertThat(intent, IntentMatchers.hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        assertThat(intent.data, `is`(CoreMatchers.nullValue()))
        val extras = intentCaptor.firstValue.extras
        assertThat(
            extras?.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), `is`(
                notNullValue()
            )
        )
        assertThat(
            extras?.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS),
            `is`(true)
        )
        assertThat(
            extras?.getParcelable<Parcelable>(AuthenticationActivity.EXTRA_CT_OPTIONS) as CustomTabsOptions?,
            `is`(options)
        )
    }

    @Test
    public fun shouldFailToStartLogoutWhenNoCompatibleBrowserAppIsInstalled() {
        val noBrowserOptions = Mockito.mock(
            CustomTabsOptions::class.java
        )
        `when`(noBrowserOptions.hasCompatibleBrowser(activity.packageManager))
            .thenReturn(false)
        logout(account)
            .withCustomTabsOptions(noBrowserOptions)
            .start(activity, voidCallback)
        verify(voidCallback).onFailure(authExceptionCaptor.capture())
        assertThat(
            authExceptionCaptor.firstValue, `is`(notNullValue())
        )
        assertThat(
            authExceptionCaptor.firstValue.getCode(),
            `is`("a0.browser_not_available")
        )
        assertThat(
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
        assertThat(uri, `is`(notNullValue()))
        val intent = createAuthIntent("")
        Assert.assertTrue(resume(intent))
        verify(voidCallback).onSuccess(eq<Void?>(null))
    }

    @Test
    public fun shouldResumeLogoutFailingWithIntent() {
        logout(account)
            .start(activity, voidCallback)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))

        //null data translates to result canceled
        val intent = createAuthIntent(null)
        Assert.assertTrue(resume(intent))
        verify(voidCallback).onFailure(authExceptionCaptor.capture())
        assertThat(
            authExceptionCaptor.firstValue,
            `is`(notNullValue())
        )
        assertThat(
            authExceptionCaptor.firstValue.getDescription(),
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

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldResumeLogoutSuccessfullyWithCoroutines(): Unit = runTest {
        val job = launch {
            logout(account)
                .await(activity, Dispatchers.Unconfined)
        }
        advanceUntilIdle()
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        val intent = createAuthIntent("")
        Assert.assertTrue(resume(intent))
        job.join()
    }

    @Test
    public fun shouldBuildDefaultLogoutURIWithCorrectSchemeHostAndPathOnLogout() {
        logout(account)
            .start(activity, voidCallback)
        val baseUriString = Uri.parse(account.logoutUrl)
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasScheme(baseUriString.scheme))
        assertThat(uri, UriMatchers.hasHost(baseUriString.host))
        assertThat(uri, UriMatchers.hasPath(baseUriString.path))
        assertThat(uri, UriMatchers.hasParamWithName("client_id"))
        assertThat(uri, UriMatchers.hasParamWithName("returnTo"))
    }


    //DPoP

    public fun shouldReturnSameInstanceWhenCallingUseDPoPMultipleTimes() {
        val provider1 = WebAuthProvider.useDPoP(mockContext)
        val provider2 = WebAuthProvider.useDPoP(mockContext)

        assertThat(provider1, `is`(provider2))
        assertThat(WebAuthProvider.useDPoP(mockContext), `is`(provider1))
    }

    @Test
    public fun shouldPassDPoPInstanceToOAuthManagerWhenDPoPIsEnabled() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(true)
        `when`(mockKeyStore.getKeyPair()).thenReturn(Pair(mock(), FakeECPublicKey()))

        WebAuthProvider.useDPoP(mockContext)
            .login(account)
            .start(activity, callback)

        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        assertThat(managerInstance.dPoP, `is`(notNullValue()))
    }

    @Test
    public fun shouldNotPassDPoPInstanceToOAuthManagerWhenDPoPIsNotEnabled() {
        login(account)
            .start(activity, callback)

        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        Assert.assertNull(managerInstance.dPoP)
    }

    @Test
    public fun shouldGenerateKeyPairWhenDPoPIsEnabledAndNoKeyPairExists() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(false)

        WebAuthProvider.useDPoP(mockContext)
            .login(account)
            .start(activity, callback)

        verify(mockKeyStore).generateKeyPair(any(), any())
    }

    @Test
    public fun shouldNotGenerateKeyPairWhenDPoPIsEnabledAndKeyPairExists() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(true)
        `when`(mockKeyStore.getKeyPair()).thenReturn(Pair(mock(), FakeECPublicKey()))

        WebAuthProvider.useDPoP(mockContext)
            .login(account)
            .start(activity, callback)

        verify(mockKeyStore, never()).generateKeyPair(any(), any())
    }

    @Test
    public fun shouldNotGenerateKeyPairWhenDPoPIsNotEnabled() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(false)

        login(account)
            .start(activity, callback)

        verify(mockKeyStore, never()).generateKeyPair(any(), any())
    }

    @Test
    public fun shouldIncludeDPoPJWKThumbprintInAuthorizeURLWhenDPoPIsEnabledAndKeyPairExists() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(true)
        `when`(mockKeyStore.getKeyPair()).thenReturn(Pair(mock(), FakeECPublicKey()))

        WebAuthProvider.useDPoP(mockContext)
            .login(account)
            .start(activity, callback)

        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithName("dpop_jkt"))
        assertThat(
            uri,
            UriMatchers.hasParamWithValue("dpop_jkt", "KQ-r0YQMCm0yVnGippcsZK4zO7oGIjOkNRbvILjjBAo")
        )
    }

    @Test
    public fun shouldNotIncludeDPoPJWKThumbprintWhenDPoPIsEnabledButGetKeyPairReturnNull() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(true)
        `when`(mockKeyStore.getKeyPair()).thenReturn(null)

        WebAuthProvider.useDPoP(mockContext)
            .login(account)
            .start(activity, callback)

        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, not(UriMatchers.hasParamWithName("dpop_jkt")))
    }

    @Test
    public fun shouldWorkWithLoginBuilderPatternWhenDPoPIsEnabled() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(true)
        `when`(mockKeyStore.getKeyPair()).thenReturn(Pair(mock(), FakeECPublicKey()))

        val builder = WebAuthProvider.useDPoP(mockContext)
            .login(account)
            .withConnection("test-connection")

        builder.start(activity, callback)

        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri, UriMatchers.hasParamWithValue("connection", "test-connection"))
        assertThat(uri, UriMatchers.hasParamWithName("dpop_jkt"))
    }

    @Test
    public fun shouldNotAffectLogoutWhenDPoPIsEnabled() {
        WebAuthProvider.useDPoP(mockContext)
            .logout(account)
            .start(activity, voidCallback)

        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        // Logout should not have DPoP parameters
        assertThat(uri, not(UriMatchers.hasParamWithName("dpop_jkt")))
    }

    @Test
    public fun shouldHandleDPoPKeyGenerationFailureGracefully() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(false)
        doThrow(DPoPException.KEY_GENERATION_ERROR)
            .`when`(mockKeyStore).generateKeyPair(any(), any())

        WebAuthProvider.useDPoP(mockContext)
            .login(account)
            .start(activity, callback)

        // Verify that the authentication fails when DPoP key generation fails
        verify(callback).onFailure(authExceptionCaptor.capture())
        val capturedException = authExceptionCaptor.firstValue
        assertThat(capturedException, `is`(instanceOf(AuthenticationException::class.java)))

        assertThat(capturedException.message, containsString("Error generating DPoP key pair."))
        assertThat(capturedException.cause, Matchers.instanceOf(DPoPException::class.java))

        verify(activity, never()).startActivity(any())
    }

    @Test
    @Throws(Exception::class)
    public fun shouldResumeLoginSuccessfullyWithDPoPEnabled() {
        `when`(mockKeyStore.hasKeyPair()).thenReturn(true)
        `when`(mockKeyStore.getKeyPair()).thenReturn(Pair(FakeECPrivateKey(), FakeECPublicKey()))

        val expiresAt = Date()
        val pkce = Mockito.mock(PKCE::class.java)
        `when`(pkce.codeChallenge).thenReturn("challenge")
        val mockAPI = AuthenticationAPIMockServer()
        mockAPI.willReturnValidJsonWebKeys()
        val authCallback = mock<Callback<Credentials, AuthenticationException>>()
        val proxyAccount: Auth0 = Auth0.getInstance(JwtTestUtils.EXPECTED_AUDIENCE, mockAPI.domain)
        proxyAccount.networkingClient = SSLTestUtils.testClient

        WebAuthProvider.useDPoP(mockContext)
            .login(proxyAccount)
            .withPKCE(pkce)
            .start(activity, authCallback)

        val managerInstance = WebAuthProvider.managerInstance as OAuthManager
        managerInstance.currentTimeInMillis = JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS
        verify(activity).startActivity(intentCaptor.capture())
        val uri =
            intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        assertThat(uri, `is`(notNullValue()))
        val sentState = uri?.getQueryParameter(KEY_STATE)
        val sentNonce = uri?.getQueryParameter(KEY_NONCE)

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
            "DPoP", // Token type should be DPoP when DPoP is enabled
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
        verify(authCallback).onSuccess(credentialsCaptor.capture())
        val credentials = credentialsCaptor.firstValue
        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.type, `is`("DPoP"))
        mockAPI.shutdown()
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