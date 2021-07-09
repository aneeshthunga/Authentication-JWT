package com.aneesh.auth.configuration

import com.aneesh.auth.service.AuthService
import com.aneesh.auth.util.JwtFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.BeanIds.AUTHENTICATION_MANAGER
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

/**
 * Security configuration for Spring Boot
 */
@Configuration
@EnableWebSecurity
class SecurityConfigurer (
    @Autowired
    private val authService: AuthService,

    @Autowired
    private val jwtFilter: JwtFilter
) : WebSecurityConfigurerAdapter() {


    override fun configure(auth: AuthenticationManagerBuilder?) {
        auth?.userDetailsService(authService)
    }

    override fun configure(http: HttpSecurity?) {
        http
            ?.csrf()
            ?.disable()
            ?.authorizeRequests()
            ?.antMatchers("/auth/sign-up", "/auth/sign-in")
            ?.permitAll()
            ?.anyRequest()
            ?.authenticated()
            ?.and()
            ?.exceptionHandling()
            ?.and()
            ?.sessionManagement()
            ?.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        http?.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter::class.java)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean(name = [AUTHENTICATION_MANAGER])
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }
}
