package com.aneesh.auth.controller

import com.aneesh.auth.dto.AuthRequest
import com.aneesh.auth.dto.AuthResponse
import com.aneesh.auth.model.User
import com.aneesh.auth.service.AuthService
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException

private val logger =  KotlinLogging.logger{ }

/**
 * A rest controller to provide authentication to a [User]
 */
@RestController
@RequestMapping("/auth")
class AuthController(
    @Autowired
    private val authService: AuthService,
    @Autowired
    private val authenticationManager: AuthenticationManager,
    @Autowired
    private val passwordEncoder: PasswordEncoder
) {

    /**
     * Test endpoint to check whether a [User] has been successfully authenticated
     * @return a string message
     */
    @GetMapping("")
    fun testAuth(): String {
        return "authenticated successfully"
    }

    /**
     * Sign in endpoint. To be used when a [User] is to be authenticated.
     * @param authRequest A JSON containing the necessary information for authentication
     * @return [AuthResponse] containing the JWT token
     */
    @PostMapping("/sign-in")
    fun signIn(@RequestBody authRequest: AuthRequest): AuthResponse {
        try {
            authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(
                    authRequest.username,
                    authRequest.password
                )
            )
            val user = User(authRequest.username, passwordEncoder.encode(authRequest.password))
            return authService.createToken(user) ?:
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Failed to authenticate user")
        } catch (e: BadCredentialsException) {
            logger.error(e) { "Failed to authenticate, username or password is incorrect: $e" }
            throw Exception("Failed to authenticate, username or password is incorrect", e)
        }
    }

    /**
     * Sign up endpoint. To be used when a new [User] wants to register.
     * @param authRequest A JSON containing the necessary information for authentication
     * @return [AuthResponse] containing a JWT token
     */
    @PostMapping("/sign-up")
    fun signUp(@RequestBody authRequest: AuthRequest): AuthResponse {

        val user = User(authRequest.username, passwordEncoder.encode(authRequest.password))
        return authService.createUserAndReturnToken(user) ?:
        throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Failed to create user")

    }
}
