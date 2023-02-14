package io.security.corespringsecurity.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

    //테스트용 인메모리 유저
    @Bean
    public UserDetailsManager users() {
        String password = passwordEncoder().encode("1111");
        UserDetails user = User.builder()
                .username( "user" )
                //.password("{noop}1111")
                .password( password )
                .roles( "USER" )
                .build();
        UserDetails manager = User.builder()
                .username("manager")
                .password( password )
                .roles("MANAGER", "USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password( password )
                .roles("ADMIN", "MANAGER", "USER")
                .build();
        return new InMemoryUserDetailsManager( user, manager, admin );
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()

                .and()
                .formLogin();

        return http.build();
    }

}
