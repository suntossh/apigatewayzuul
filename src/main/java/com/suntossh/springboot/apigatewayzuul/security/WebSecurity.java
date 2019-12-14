package com.suntossh.springboot.apigatewayzuul.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	private Environment environment;

	@Autowired
	public WebSecurity(Environment environment) {
		super();
		this.environment = environment;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();// Not 100% sure
		http.headers().frameOptions().disable();// enables h2 console to display
		http.authorizeRequests().antMatchers(HttpMethod.POST, environment.getProperty("users.registration.path")).permitAll()
		.antMatchers(HttpMethod.POST, environment.getProperty("users.login.path")).permitAll()
		.antMatchers(environment.getProperty("users.h2console.path")).permitAll()
		.anyRequest().authenticated();// which means it must have the valid token in the Request
	}
}
