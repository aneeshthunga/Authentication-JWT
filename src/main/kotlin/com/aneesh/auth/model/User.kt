package com.aneesh.auth.model

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.Id


@Entity
data class User (
    @Column(unique = true) private var username: String,
    private var password: String,
    var accountNonExpired: Boolean = true,
    var accountNonLocked: Boolean = true,
    var enabled: Boolean = true,
    var credentialsNonExpired: Boolean = true,
    @Id @GeneratedValue var id: Long? = null
) : UserDetails {
    override fun getPassword(): String = password

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return mutableListOf()
    }

    override fun getUsername(): String = username

    override fun isAccountNonExpired(): Boolean = accountNonExpired

    override fun isAccountNonLocked(): Boolean = accountNonLocked

    override fun isCredentialsNonExpired(): Boolean = credentialsNonExpired

    override fun isEnabled(): Boolean = enabled

    override fun toString(): String {
        return "User(username: $username)"
    }
}
