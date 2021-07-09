package com.aneesh.auth.util

import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import mu.KotlinLogging
import org.springframework.security.core.userdetails.UserDetails
import java.util.*
import javax.crypto.SecretKey
import kotlin.collections.HashMap

private val logger = KotlinLogging.logger{ }

/**
 * Encryption Key for generating JWT tokens
 */
internal val SECRET_KEY: SecretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512)

/**
 * Generates a JWT token for the given [UserDetails] and validity duration
 *
 * @param userDetails the given [UserDetails]
 * @return the JWT token
 */
fun generateToken(userDetails: UserDetails): String {
    val claims = HashMap<String, Any>()
    return createToken(claims, userDetails.username)
}

/**
 * Creates  a token with the given claims, subject and validity duration
 *
 * @param claims the given claims
 * @param subject the given subject
 * @return JWT token
 */
fun createToken(claims: Map<String, Any>, subject: String): String {
    //5 hours validity
    var expirationDate = Date(System.currentTimeMillis() + 1000 * 60 * 60 * 5)

    return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(Date(System.currentTimeMillis()))
        .setExpiration(expirationDate)
        .signWith(SECRET_KEY, SignatureAlgorithm.HS512).compact()
}


/**
 * Returns whether a token is valid or not
 *
 * @param token whose validity is to be checked
 * @return true if valid, false otherwise
 */
fun isValidToken(token: String): Boolean {
    return !isTokenExpired(token)
}

/**
 * Extracts all claims for a given JWT token
 *
 * @param token the given JWT token
 * @return claims extracted from the token
 */
fun extractAllClaims(token: String): Claims = Jwts.parserBuilder().setSigningKey(SECRET_KEY).build()
    .parseClaimsJws(token).body

/**
 * Extracts a single claim from the given token and a resolver function
 *
 * @param T Type of claim
 * @param token JWT token
 * @param claimsResolver A lambda which takes in a claim and returns T
 * @receiver
 * @return returns an extracted claim of type T
 */
fun <T> extractClaim(token: String, claimsResolver: (Claims) -> T): T {
    val claims = extractAllClaims(token)
    return claimsResolver(claims)
}

/**
 * Returns if a given JWT token is expired or not
 *
 * @param token the given JWT token
 * @return true if expired, false otherwise
 */
fun isTokenExpired(token: String): Boolean {
    return try {
        extractExpiration(token).before(Date())
    }
    catch (e: ExpiredJwtException) {
        logger.warn(e) { "token expired" }
        true
    }
}

/**
 * Extracts expiration date for a given JWT token
 *
 * @param token given JWT token
 * @return the expiration [Date]
 */
fun extractExpiration(token: String): Date = extractClaim(token, Claims::getExpiration)

/**
 * Extracts username for a given JWT token
 *
 * @param token given JWT token
 * @return the username of the [User]
 */
fun extractUsername(token: String): String = extractClaim(token, Claims::getSubject)

fun getTokenFromAuthHeader(authHeader: String): String? {
    return if (authHeader.startsWith("Bearer")) {
        authHeader.substring(7)
    }
    else {
        null
    }
}
