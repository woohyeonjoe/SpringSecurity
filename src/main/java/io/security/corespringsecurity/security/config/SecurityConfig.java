package io.security.corespringsecurity.security.config;

import io.security.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

    //테스트용 인메모리 유저
    /*
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
    */

    //CustomAuthenticationProvider 내부에서 UserDetailsService를 사용하도록 구현해서 등록에서 제외해주었다.
    /*
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        return authConfiguration.getAuthenticationManager();
    }
     */

    @Autowired
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler customAuthenticationFailureHandler;

    @Autowired
    private FormAuthenticationDetailsSource authenticationDetailsSource;

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
            web.ignoring().antMatchers("/favicon.ico", "/resources/**", "/error");
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/", "/users", "user/login/**", "/login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()

                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)   //WebAuthenticationDetails 추가
                .defaultSuccessUrl("/")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll()

                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());


        http    //UsernamePasswordAuthenticationFilter 앞에서 작동하게 설정
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);



        return http.build();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Bean AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        return authConfiguration.getAuthenticationManager();
    }

    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() {
        return new AjaxLoginProcessingFilter();
    }



}
