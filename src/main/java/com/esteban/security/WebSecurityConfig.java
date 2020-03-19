package com.esteban.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        // All requests send to the Web Server request must be authenticated
        http.authorizeRequests()
                .antMatchers("/css/**", "/login")
                .permitAll()
                .anyRequest().authenticated();

        // Use login page
        http
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .httpBasic()
                //.loginProcessingUrl("/perform_login")
                //.defaultSuccessUrl("/index.html", true)
                //.failureUrl("/login.html?error=true")
                //.failureHandler(authenticationFailureHandler())
                .and()
                .logout()
//                //.logoutUrl("/perform_logout")
                .deleteCookies("JSESSIONID")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .permitAll()
        //.logoutSuccessHandler(logoutSuccessHandler())
        ;
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .ldapAuthentication()
                .userDnPatterns("uid={0},ou=people")
                .userSearchBase("ou=people")
                .groupSearchBase("ou=groups")
                .contextSource()
                .url("ldap://localhost:8389/dc=springframework,dc=org")
                .and()
                .passwordCompare()
                .passwordEncoder(new LdapShaPasswordEncoder())
                //.passwordEncoder(new BCryptPasswordEncoder())
                .passwordAttribute("userPassword");
    }

}