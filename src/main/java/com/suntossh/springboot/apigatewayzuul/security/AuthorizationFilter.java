package com.suntossh.springboot.apigatewayzuul.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class AuthorizationFilter extends BasicAuthenticationFilter{

	Environment environment;
	
	
	public AuthorizationFilter(AuthenticationManager authenticationManager, Environment environment) {
		super(authenticationManager);
		this.environment = environment;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String authHeader = request.getHeader(environment.getProperty("authorization.token.header.name"));
		if(authHeader == null || !authHeader.startsWith(environment.getProperty("authorization.token.header.prefix"))) {
			chain.doFilter(request, response);
			return;
		}
		
		UsernamePasswordAuthenticationToken usernamePasswordAuthentication =   getAuthentication(request);
		
		SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthentication);
		chain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String authHeader = request.getHeader(environment.getProperty("authorization.token.header.name"));
		
		if(authHeader == null) {
			return null;
		}
		String token = authHeader.replace(environment.getProperty("authorization.token.header.prefix"), "");
		String userId = Jwts.parser().setSigningKey(environment.getProperty("token.secret.key")).parseClaimsJws(token).getBody().getSubject();
		
		return (userId==null?null:new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>()));
		
	}

}
