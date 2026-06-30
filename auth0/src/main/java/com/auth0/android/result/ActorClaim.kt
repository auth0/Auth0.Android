package com.auth0.android.result

import java.io.Serializable

/**
 * Represents the `act` (actor) claim in an ID token, used in delegation and impersonation scenarios.
 * See RFC 8693 Section 4.4 for the specification of the `act` claim.
 *
 * @param sub The unique identifier of the actor (required).
 * @param actor A nested actor claim representing a delegation chain.
 * @param extraProperties Additional custom properties set via the `setActor` Action command.
 */
public data class ActorClaim(
    val sub: String,
    val actor: ActorClaim? = null,
    val extraProperties: Map<String, Any> = emptyMap()
) : Serializable
