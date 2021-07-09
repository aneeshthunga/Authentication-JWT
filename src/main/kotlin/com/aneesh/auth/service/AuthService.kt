package com.aneesh.auth.service

import com.aneesh.auth.dto.AuthResponse
import com.aneesh.auth.model.User
import com.aneesh.auth.repository.UserRepository
import com.aneesh.auth.util.generateToken
import io.jsonwebtoken.JwtException
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service

private val logger = KotlinLogging.logger{}

/**
 * Auth service class which handles Authentication and Authorization
 *
 * @property userRepository injected [UserRepository]
 * @constructor handled by Spring
 */
@Service
class AuthService(@Autowired private val userRepository: UserRepository) : UserDetailsService {
    override fun loadUserByUsername(username: String): UserDetails? = userRepository.findByUsername(username)

    /**
     * Checks if a [User] with the given username exists in the database
     * @param userDetails which contains username and password
     * @return true if [User] exists already, false otherwise
     */
    fun isUserExists(userDetails: UserDetails): Boolean {
        val username = userDetails.username
        val user = loadUserByUsername(username)
        return user != null
    }

    /**
     * Creates a [User] by storing the given [User] in the database and returns a JWT token
     * @param user the given [User]
     * @return [AuthResponse] containing a JWT if a [User] was successfully created
     */
    fun createUserAndReturnToken(user: User): AuthResponse? {
        return if (!isUserExists(user)) {
            userRepository.save(user)
            logger.info { "Successfully added new user to db: $user" }
            createToken(user)
        }
        else {
            logger.warn { "Failed to create user as username already exists in db for $user" }
            null
        }
    }

    /**
     * Create a JWT token for a given [User]
     * @param user the given [User]
     * @return [AuthResponse] containing the JWT token
     */
    fun createToken(user: UserDetails): AuthResponse? {
        return try {
            val jwt = generateToken(user)
            AuthResponse(jwt)
        } catch (e: JwtException) {
            logger.error(e) { "failed to create jwt" }
            null
        }
    }
}
