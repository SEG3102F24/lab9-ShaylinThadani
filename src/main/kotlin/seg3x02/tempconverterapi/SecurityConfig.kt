package seg3x02.tempconverterapi

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SecurityConfig {

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        // Define a BCrypt password encoder
        return BCryptPasswordEncoder()
    }

    @Bean
    fun userDetailsService(passwordEncoder: PasswordEncoder): UserDetailsService {
        // Create a user with username "user1" and password "pass1"
        val user1: UserDetails = User.withUsername("user1")
            .password(passwordEncoder.encode("pass1"))
            .roles("USER")
            .build()

        // Create another user with username "user2" and password "pass2"
        val user2: UserDetails = User.withUsername("user2")
            .password(passwordEncoder.encode("pass2"))
            .roles("USER")
            .build()

        // Return an in-memory user details manager with the defined users
        return InMemoryUserDetailsManager(user1, user2)
    }

    @Bean
    @Throws(Exception::class)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf().disable() // Disable csrf protection
            .authorizeRequests { auth ->
                auth.anyRequest().authenticated() // require authentication for all requests
            }
            .httpBasic() // http Basic Authentication
        return http.build() // build and return the security filter chain
    }
}