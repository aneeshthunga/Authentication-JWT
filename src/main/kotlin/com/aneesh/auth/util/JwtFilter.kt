package com.aneesh.auth.util

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * A http request filter used to authenticate the [User] using the provided JWT token
 */
@Component
class JwtFilter : OncePerRequestFilter() {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val authorizationHeader: String? = request.getHeader("Authorization")
        var token: String? = null
        var username: String? = null
        if (authorizationHeader != null) {
            token = getTokenFromAuthHeader(authorizationHeader)
            username = extractUsername(token!!)
        }
        if (username != null && SecurityContextHolder.getContext().authentication == null) {
            if (isValidToken(token!!)) {
                val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(
                    username, null, emptySet()
                )
                usernamePasswordAuthenticationToken.details = WebAuthenticationDetailsSource().buildDetails(request)
                SecurityContextHolder.getContext().authentication = usernamePasswordAuthenticationToken
            }
        }
        filterChain.doFilter(request, response)
    }
}
