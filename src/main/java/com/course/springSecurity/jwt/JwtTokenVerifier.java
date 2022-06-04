package com.course.springSecurity.jwt;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public class JwtTokenVerifier extends OncePerRequestFilter{
	
	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;
	
	public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
		this.jwtConfig = jwtConfig;
		this.secretKey = secretKey;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());    
		if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
			filterChain.doFilter(request, response);
			return;
		}
		
		String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

		try {
			
			@SuppressWarnings("deprecation")
			Jws<Claims> claimsJws = Jwts.parser()    // A signed JWT is called JWS
										.setSigningKey(secretKey)
										.parseClaimsJws(token);	
			Claims body = claimsJws.getBody();
			String username = body.getSubject();
			
			@SuppressWarnings("unchecked")
			var authorities = (List<Map<String, String>>) body.get("authorities");   		  // authorities JWT payload kısmında yer alan isim olmalı
			Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
					   .map(m -> new SimpleGrantedAuthority(m.get("authority")))    // authority JWT payload kısmında yer alan isim olmalı
					   .collect(Collectors.toSet());
			
			Authentication authentication = new UsernamePasswordAuthenticationToken(
					username,
					null,
					simpleGrantedAuthorities
			);
			
			SecurityContextHolder.getContext().setAuthentication(authentication);
		
		} catch(JwtException e) {
			throw new IllegalStateException(String.format("Token %s cannnot be trusted", token));
		}
		
		filterChain.doFilter(request, response);
	}

}
