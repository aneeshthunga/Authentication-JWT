package com.aneesh.auth.repository

import com.aneesh.auth.model.User
import org.springframework.data.repository.CrudRepository

/**
 * repository to interact with the [User] model
 */
interface UserRepository : CrudRepository<User, Long> {
    /**
     * Fetches a [User] from the database using their username
     *
     * @param username of the [User] to be fetched
     * @return [User] if present, null otherwise
     */
    fun findByUsername(username: String): User?
}
