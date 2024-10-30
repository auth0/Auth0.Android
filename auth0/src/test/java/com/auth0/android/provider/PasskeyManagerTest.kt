package com.auth0.android.provider

import android.content.Context
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.request.AuthenticationRequestMock
import com.auth0.android.authentication.request.RequestMock
import com.auth0.android.callback.Callback
import com.auth0.android.request.UserMetadataRequest
import com.auth0.android.result.AuthParamsPublicKey
import com.auth0.android.result.AuthenticatorSelection
import com.auth0.android.result.AuthnParamsPublicKey
import com.auth0.android.result.Credentials
import com.auth0.android.result.PasskeyChallengeResponse
import com.auth0.android.result.PasskeyRegistrationResponse
import com.auth0.android.result.PasskeyUser
import com.auth0.android.result.PubKeyCredParam
import com.auth0.android.result.RelyingParty
import com.nhaarman.mockitokotlin2.KArgumentCaptor
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.argumentCaptor
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.eq
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.never
import com.nhaarman.mockitokotlin2.verify
import com.nhaarman.mockitokotlin2.whenever
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito.`when`
import org.mockito.MockitoAnnotations
import org.robolectric.RobolectricTestRunner
import java.util.Date
import java.util.concurrent.Executor


@RunWith(RobolectricTestRunner::class)
public class PasskeyManagerTest {

    private lateinit var passkeyManager: PasskeyManager

    @Mock
    private lateinit var callback: Callback<Credentials, AuthenticationException>

    @Mock
    private lateinit var authenticationAPIClient: AuthenticationAPIClient

    @Mock
    private lateinit var credentialManager: CredentialManager

    @Mock
    private lateinit var context: Context

    private val serialExecutor = Executor { runnable -> runnable.run() }

    private val credentialsCaptor: KArgumentCaptor<Credentials> = argumentCaptor()
    private val exceptionCaptor: KArgumentCaptor<AuthenticationException> = argumentCaptor()


    private val passkeyRegistrationResponse = PasskeyRegistrationResponse(
        authSession = "dummyAuthSession",
        authParamsPublicKey = AuthnParamsPublicKey(
            authenticatorSelection = AuthenticatorSelection(
                residentKey = "required",
                userVerification = "preferred"
            ),
            challenge = "dummyChallenge",
            pubKeyCredParams = listOf(
                PubKeyCredParam(
                    alg = -7,
                    type = "public-key"
                )
            ),
            relyingParty = RelyingParty(
                id = "dummyRpId",
                name = "dummyRpName"
            ),
            timeout = 60000L,
            user = PasskeyUser(
                displayName = "displayName",
                id = "userId",
                name = "userName"
            )
        )
    )

    private val registrationResponseJSON = """
        {
            "id": "id",
            "rawId": "rawId",
            "response": {
                "attestationObject": "attnObject",
                "clientDataJSON": "dataJSON"
            },
            "type": "public-key"
        }
    """

    private val passkeyChallengeResponse = PasskeyChallengeResponse(
        authSession = "authSession",
        authParamsPublicKey = AuthParamsPublicKey(
            challenge = "challenge",
            rpId = "RpId",
            timeout = 60000,
            userVerification = "preferred"
        )
    )

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        passkeyManager = PasskeyManager(authenticationAPIClient, credentialManager)
    }


    @Test
    public fun shouldSignUpWithPasskeySuccess() {
        val userMetadata: UserMetadataRequest = mock()
        val parameters = mapOf("realm" to "testRealm")

        `when`(authenticationAPIClient.signupWithPasskey(userMetadata, parameters)).thenReturn(
            RequestMock(passkeyRegistrationResponse, null)
        )
        `when`(authenticationAPIClient.signinWithPasskey(any(), any(), any())).thenReturn(
            AuthenticationRequestMock(
                Credentials(
                    "expectedIdToken",
                    "codeAccess",
                    "codeType",
                    "codeRefresh",
                    Date(),
                    "codeScope"
                ), null
            )
        )

        val createResponse: CreatePublicKeyCredentialResponse = mock()
        `when`(createResponse.registrationResponseJson).thenReturn(
            registrationResponseJSON
        )

        whenever(
            credentialManager.createCredentialAsync(
                any(),
                any(),
                any(),
                any(),
                any()
            )
        ).thenAnswer {
            (it.arguments[4] as CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException>).onResult(
                createResponse
            )
        }

        passkeyManager.signup(context, userMetadata, parameters, callback, serialExecutor)

        verify(authenticationAPIClient).signupWithPasskey(userMetadata, parameters)
        verify(credentialManager).createCredentialAsync(eq(context), any(), any(), any(), any())
        verify(authenticationAPIClient).signinWithPasskey(any(), any(), any())
        verify(callback).onSuccess(credentialsCaptor.capture())
        Assert.assertEquals("codeAccess", credentialsCaptor.firstValue.accessToken)
        Assert.assertEquals("codeScope", credentialsCaptor.firstValue.scope)

    }

    @Test
    public fun shouldSignUpWithPasskeyApiFailure() {
        val userMetadata: UserMetadataRequest = mock()
        val parameters = mapOf("realm" to "testRealm")
        val error = AuthenticationException("Signup failed")
        `when`(
            authenticationAPIClient.signupWithPasskey(
                userMetadata,
                parameters
            )
        ).thenReturn(RequestMock(null, error))
        passkeyManager.signup(context, userMetadata, parameters, callback, serialExecutor)
        verify(authenticationAPIClient).signupWithPasskey(userMetadata, parameters)
        verify(authenticationAPIClient, never()).signinWithPasskey(any(), any(), any())
        verify(credentialManager, never()).createCredentialAsync(
            any(),
            any(),
            any(),
            any(),
            any()
        )
        verify(callback).onFailure(error)
    }

    @Test
    public fun shouldSignUpWithPasskeyCreateCredentialFailure() {
        val userMetadata: UserMetadataRequest = mock()
        val parameters = mapOf("realm" to "testRealm")
        `when`(
            authenticationAPIClient.signupWithPasskey(
                userMetadata,
                parameters
            )
        ).thenReturn(RequestMock(passkeyRegistrationResponse, null))

        whenever(
            credentialManager.createCredentialAsync(
                any(),
                any(),
                any(),
                any(),
                any()
            )
        ).thenAnswer {
            (it.arguments[4] as CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException>).onError(
                CreateCredentialInterruptedException()
            )
        }

        passkeyManager.signup(context, userMetadata, parameters, callback, serialExecutor)
        verify(authenticationAPIClient).signupWithPasskey(userMetadata, parameters)
        verify(credentialManager).createCredentialAsync(eq(context), any(), any(), any(), any())
        verify(authenticationAPIClient, never()).signinWithPasskey(any(), any(), any())
        verify(callback).onFailure(exceptionCaptor.capture())
        Assert.assertEquals(
            AuthenticationException::class.java,
            exceptionCaptor.firstValue.javaClass
        )
        Assert.assertEquals(
            "Passkey authentication was interrupted. Please retry the call.",
            exceptionCaptor.firstValue.message
        )
    }


    @Test
    public fun shouldSignInWithPasskeySuccess() {
        val parameters = mapOf("realm" to "testRealm")
        val credentialResponse: GetCredentialResponse = mock()

        `when`(authenticationAPIClient.passkeyChallenge(parameters["realm"])).thenReturn(
            RequestMock(passkeyChallengeResponse, null)
        )

        `when`(credentialResponse.credential).thenReturn(
            PublicKeyCredential(registrationResponseJSON)
        )

        `when`(authenticationAPIClient.signinWithPasskey(any(), any(), any())).thenReturn(
            AuthenticationRequestMock(
                Credentials(
                    "expectedIdToken",
                    "codeAccess",
                    "codeType",
                    "codeRefresh",
                    Date(),
                    "codeScope"
                ), null
            )
        )

        doAnswer {
            val callback =
                it.getArgument<CredentialManagerCallback<GetCredentialResponse, GetCredentialException>>(
                    4
                )
            callback.onResult(credentialResponse)
        }.`when`(credentialManager)
            .getCredentialAsync(any(), any<GetCredentialRequest>(), any(), any(), any())

        passkeyManager.signin(context, parameters, callback, serialExecutor)

        verify(authenticationAPIClient).passkeyChallenge(parameters["realm"])
        verify(credentialManager).getCredentialAsync(
            any(),
            any<GetCredentialRequest>(),
            any(),
            any(),
            any()
        )
        verify(authenticationAPIClient).signinWithPasskey(any(), any(), any())
        verify(callback).onSuccess(credentialsCaptor.capture())
        Assert.assertEquals("codeAccess", credentialsCaptor.firstValue.accessToken)
        Assert.assertEquals("codeScope", credentialsCaptor.firstValue.scope)
    }


    @Test
    public fun shouldSignInWithPasskeyApiFailure() {
        val parameters = mapOf("realm" to "testRealm")
        val error = AuthenticationException("Signin failed")

        `when`(authenticationAPIClient.passkeyChallenge(parameters["realm"])).thenReturn(
            RequestMock(null, error)
        )

        passkeyManager.signin(context, parameters, callback, serialExecutor)

        verify(authenticationAPIClient).passkeyChallenge(any())
        verify(credentialManager, never()).getCredentialAsync(
            any(),
            any<GetCredentialRequest>(),
            any(),
            any(),
            any()
        )
        verify(authenticationAPIClient, never()).signinWithPasskey(any(), any(), any())
        verify(callback).onFailure(error)
    }

    @Test
    public fun shouldSignInWithPasskeyGetCredentialFailure() {
        val parameters = mapOf("realm" to "testRealm")
        `when`(authenticationAPIClient.passkeyChallenge(parameters["realm"])).thenReturn(
            RequestMock(passkeyChallengeResponse, null)
        )

        whenever(
            credentialManager.getCredentialAsync(
                any(),
                any<GetCredentialRequest>(),
                any(),
                any(),
                any()
            )
        ).thenAnswer {
            (it.arguments[4] as CredentialManagerCallback<GetCredentialResponse, GetCredentialException>).onError(
                GetCredentialInterruptedException()
            )
        }

        passkeyManager.signin(context, parameters, callback, serialExecutor)
        verify(authenticationAPIClient).passkeyChallenge(parameters["realm"])
        verify(credentialManager).getCredentialAsync(
            any(),
            any<GetCredentialRequest>(),
            any(),
            any(),
            any()
        )
        verify(authenticationAPIClient, never()).signinWithPasskey(any(), any(), any())
        verify(callback).onFailure(exceptionCaptor.capture())
        Assert.assertEquals(
            AuthenticationException::class.java,
            exceptionCaptor.firstValue.javaClass
        )
        Assert.assertEquals(
            "Passkey authentication was interrupted. Please retry the call.",
            exceptionCaptor.firstValue.message
        )
    }
}