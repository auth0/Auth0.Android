package com.auth0.android.request.internal

import com.auth0.android.result.UserIdentity
import com.auth0.android.result.UserProfile
import com.auth0.android.util.UserIdentityMatcher
import com.auth0.android.util.UserProfileMatcher
import com.google.gson.JsonParseException
import org.hamcrest.MatcherAssert
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers
import org.hamcrest.Matchers.*
import org.hamcrest.collection.IsMapWithSize
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.io.StringReader
import java.text.SimpleDateFormat
import java.util.*

public class UserProfileGsonTest : GsonBaseTest() {

    @Before
    public fun setUp() {
        gson = GsonProvider.gson
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailWithInvalidJson() {
        Assert.assertThrows(JsonParseException::class.java) {
            pojoFrom(json(INVALID), UserProfile::class.java)
        }
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailWithEmptyJson() {
        Assert.assertThrows(JsonParseException::class.java) {
            pojoFrom(json(EMPTY_OBJECT), UserProfile::class.java)
        }
    }

    @Test
    @Throws(Exception::class)
    public fun shouldNotRequireUserId() {
        val userProfile = pojoFrom(
            StringReader(
                """{
  "picture": "https://secure.gravatar.com/avatar/cfacbe113a96fdfc85134534771d88b4?s=480&r=pg&d=https%3A%2F%2Fssl.gstatic.com%2Fs2%2Fprofiles%2Fimages%2Fsilhouette80.png",
  "name": "info @ auth0",
  "nickname": "a0",
  "identities": [
    {
      "user_id": "1234567890",
      "provider": "auth0",
      "connection": "Username-Password-Authentication",
      "isSocial": false
    }
  ],
  "created_at": "2014-07-06T18:33:49.005Z"
}"""
            ), UserProfile::class.java
        )
        MatcherAssert.assertThat(userProfile, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldNotRequireName() {
        val userProfile = pojoFrom(
            StringReader(
                """{
  "picture": "https://secure.gravatar.com/avatar/cfacbe113a96fdfc85134534771d88b4?s=480&r=pg&d=https%3A%2F%2Fssl.gstatic.com%2Fs2%2Fprofiles%2Fimages%2Fsilhouette80.png",
  "nickname": "a0",
  "user_id": "auth0|1234567890",
  "identities": [
    {
      "user_id": "1234567890",
      "provider": "auth0",
      "connection": "Username-Password-Authentication",
      "isSocial": false
    }
  ],
  "created_at": "2014-07-06T18:33:49.005Z"
}"""
            ), UserProfile::class.java
        )
        MatcherAssert.assertThat(userProfile, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldNotRequireNickname() {
        val userProfile = pojoFrom(
            StringReader(
                """{
  "picture": "https://secure.gravatar.com/avatar/cfacbe113a96fdfc85134534771d88b4?s=480&r=pg&d=https%3A%2F%2Fssl.gstatic.com%2Fs2%2Fprofiles%2Fimages%2Fsilhouette80.png",
  "name": "info @ auth0",
  "user_id": "auth0|1234567890",
  "identities": [
    {
      "user_id": "1234567890",
      "provider": "auth0",
      "connection": "Username-Password-Authentication",
      "isSocial": false
    }
  ],
  "created_at": "2014-07-06T18:33:49.005Z"
}"""
            ), UserProfile::class.java
        )
        MatcherAssert.assertThat(userProfile, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldNotRequirePicture() {
        val userProfile = pojoFrom(
            StringReader(
                """{
  "name": "info @ auth0",
  "nickname": "a0",
  "user_id": "auth0|1234567890",
  "identities": [
    {
      "user_id": "1234567890",
      "provider": "auth0",
      "connection": "Username-Password-Authentication",
      "isSocial": false
    }
  ],
  "created_at": "2014-07-06T18:33:49.005Z"
}"""
            ), UserProfile::class.java
        )
        MatcherAssert.assertThat(userProfile, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnOAuthProfile() {
        val profile = pojoFrom(json(PROFILE_OAUTH), UserProfile::class.java)
        MatcherAssert.assertThat(
            profile.getId(),
            Matchers.`is`("google-oauth2|9883254263433883220")
        )
        MatcherAssert.assertThat(profile.name, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(profile.nickname, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(profile.pictureURL, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(
            profile.getIdentities(), Matchers.`is`(
                Matchers.emptyCollectionOf(
                    UserIdentity::class.java
                )
            )
        )
        MatcherAssert.assertThat(profile.getUserMetadata(), IsMapWithSize.anEmptyMap())
        MatcherAssert.assertThat(profile.getAppMetadata(), IsMapWithSize.anEmptyMap())
        MatcherAssert.assertThat(profile.getExtraInfo(), IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(
            profile.getExtraInfo(),
            Matchers.hasEntry("sub", "google-oauth2|9883254263433883220" as Any)
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnProfileWithOnlyRequiredValues() {
        val profile = pojoFrom(json(PROFILE_BASIC), UserProfile::class.java)
        MatcherAssert.assertThat(
            profile,
            UserProfileMatcher.isNormalizedProfile(ID, NAME, NICKNAME)
        )
        MatcherAssert.assertThat(profile.getIdentities(), Matchers.hasSize(1))
        MatcherAssert.assertThat(
            profile.getIdentities(),
            Matchers.hasItem(
                UserIdentityMatcher.isUserIdentity(
                    "1234567890",
                    "auth0",
                    "Username-Password-Authentication"
                )
            )
        )
        MatcherAssert.assertThat(profile.getUserMetadata(), IsMapWithSize.anEmptyMap())
        MatcherAssert.assertThat(profile.getAppMetadata(), IsMapWithSize.anEmptyMap())
        MatcherAssert.assertThat(profile.getExtraInfo(), IsMapWithSize.anEmptyMap())
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnNormalizedProfile() {
        val profile = pojoFrom(json(PROFILE), UserProfile::class.java)
        MatcherAssert.assertThat(
            profile,
            UserProfileMatcher.isNormalizedProfile(ID, NAME, NICKNAME)
        )
        MatcherAssert.assertThat(profile.getIdentities(), Matchers.hasSize(1))
        MatcherAssert.assertThat(
            profile.getIdentities(),
            Matchers.hasItem(
                UserIdentityMatcher.isUserIdentity(
                    "1234567890",
                    "auth0",
                    "Username-Password-Authentication"
                )
            )
        )
        MatcherAssert.assertThat(profile.getUserMetadata(), IsMapWithSize.anEmptyMap())
        MatcherAssert.assertThat(profile.getAppMetadata(), IsMapWithSize.anEmptyMap())
        MatcherAssert.assertThat(profile.getExtraInfo(), Matchers.notNullValue())
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnProfileWithOptionalFields() {
        val profile = pojoFrom(json(PROFILE_FULL), UserProfile::class.java)
        MatcherAssert.assertThat(
            profile,
            UserProfileMatcher.isNormalizedProfile(ID, NAME, NICKNAME)
        )
        MatcherAssert.assertThat(profile.email, Matchers.equalTo("info@auth0.com"))
        MatcherAssert.assertThat(profile.givenName, Matchers.equalTo("John"))
        MatcherAssert.assertThat(profile.familyName, Matchers.equalTo("Foobar"))
        MatcherAssert.assertThat(profile.isEmailVerified, Matchers.`is`(false))
        MatcherAssert.assertThat(
            profile.createdAt,
            Matchers.equalTo(
                SimpleDateFormat(
                    "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
                    Locale.US
                ).parse("2014-07-06T18:33:49.005Z")
            )
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnProfileWithMultipleIdentities() {
        val profile = pojoFrom(json(PROFILE_FULL), UserProfile::class.java)
        MatcherAssert.assertThat(
            profile,
            UserProfileMatcher.isNormalizedProfile(ID, NAME, NICKNAME)
        )
        MatcherAssert.assertThat(
            profile.getIdentities(),
            Matchers.hasItem(
                UserIdentityMatcher.isUserIdentity(
                    "1234567890",
                    "auth0",
                    "Username-Password-Authentication"
                )
            )
        )
        MatcherAssert.assertThat(
            profile.getIdentities(),
            Matchers.hasItem(
                UserIdentityMatcher.isUserIdentity(
                    "999997950999976",
                    "facebook",
                    "facebook"
                )
            )
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnProfileWithExtraInfo() {
        val profile = pojoFrom(json(PROFILE_FULL), UserProfile::class.java)
        MatcherAssert.assertThat(
            profile,
            UserProfileMatcher.isNormalizedProfile(ID, NAME, NICKNAME)
        )
        MatcherAssert.assertThat(
            profile.getExtraInfo(),
            Matchers.hasEntry("multifactor", listOf("google-authenticator"))
        )
        assertThat(
            profile.getExtraInfo(),
            not(
                anyOf(
                    hasKey("user_id"),
                    hasKey("name"),
                    hasKey("nickname"),
                    hasKey("picture"),
                    hasKey("email"),
                    hasKey("created_at")
                )
            )
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnProfileWithMetadata() {
        val profile = pojoFrom(json(PROFILE_FULL), UserProfile::class.java)
        MatcherAssert.assertThat(
            profile,
            UserProfileMatcher.isNormalizedProfile(ID, NAME, NICKNAME)
        )
        MatcherAssert.assertThat(
            profile.getUserMetadata(),
            Matchers.hasEntry("first_name", "Info" as Any)
        )
        MatcherAssert.assertThat(
            profile.getUserMetadata(),
            Matchers.hasEntry("last_name", "Auth0" as Any)
        )
        MatcherAssert.assertThat(
            profile.getUserMetadata(),
            Matchers.hasEntry("first_name", "Info" as Any)
        )
        MatcherAssert.assertThat(
            profile.getAppMetadata(),
            Matchers.hasEntry("role", "admin" as Any)
        )
        MatcherAssert.assertThat(profile.getAppMetadata(), Matchers.hasEntry("tier", 2.0 as Any))
        MatcherAssert.assertThat(
            profile.getAppMetadata(),
            Matchers.hasEntry("blocked", false as Any)
        )
    }

    private companion object {
        private const val NICKNAME = "a0"
        private const val NAME = "info @ auth0"
        private const val ID = "auth0|1234567890"
        private const val PROFILE_OAUTH = "src/test/resources/profile_oauth.json"
        private const val PROFILE_FULL = "src/test/resources/profile_full.json"
        private const val PROFILE_BASIC = "src/test/resources/profile_basic.json"
        private const val PROFILE = "src/test/resources/profile.json"
    }
}