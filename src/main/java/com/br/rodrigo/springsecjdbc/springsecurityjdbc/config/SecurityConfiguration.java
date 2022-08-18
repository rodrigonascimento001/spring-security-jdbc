package com.br.rodrigo.springsecjdbc.springsecurityjdbc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true) // anotation necessaria para usar o pre post autorize
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
       return  http.authorizeRequests()
                //endpoints publicos
                .antMatchers("/").permitAll() // area nao logada
                //endpoints privados
              // .antMatchers("/admin").hasRole("ADMIN") // autorizar usuario pelo perfil
               .anyRequest().authenticated()
               .and().formLogin().loginPage("/login").permitAll()
                .and().logout().logoutUrl("/logout")
                .and()
                .exceptionHandling().accessDeniedPage("/403")
                .and().csrf().disable().build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        String userByUserNameQuery = "SELECT username, password, enabled from USERS where username =?";
        String authoritiesByUserQuery = "SELECT username, authority from AUTHORITIES where username =?";
        var userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.setUsersByUsernameQuery(userByUserNameQuery);
        userDetailsManager.setAuthoritiesByUsernameQuery(authoritiesByUserQuery);
        return userDetailsManager;
    }
}
