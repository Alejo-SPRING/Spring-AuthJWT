package com.practica.backEnd.app.web.auth.services;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.practica.backEnd.app.web.auth.SimpleGrantedAuthoritiesMixin;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JWTServiceImpl implements IJWTService {
	
	//creamos el codigo secreto
	public static final Key SECRET_KEY = new SecretKeySpec("alguna.clave.secreta.123456789.algo".getBytes(), SignatureAlgorithm.HS256.getJcaName());
	public static final String TOKEN_PREFIX = "Bearer ";
	
	@Override
	public String create(Authentication auth) throws JsonProcessingException {
		//traemos el id o username de SpringSecurity
		String userName = auth.getName();

		// en este objeto es donde se guardan los roles en el token, este es el payload
		Claims claims = Jwts.claims();
		// agregamos lo roles
		claims.put("authorities", new ObjectMapper().writeValueAsString(auth.getAuthorities()));

		// creamos el token, asignando el nombre del usuario logeado y la clave secreta
		// creada
		String token = Jwts.builder()
				.setClaims(claims)
				.setSubject(userName)
				.signWith(SECRET_KEY)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + 140000))
				.compact();
		return token;
	}

	@Override
	public boolean validate(String token) {
		try {
			getClaims(token);
			return true;
		} catch (JwtException e) {
			return false;
		}
	}

	@Override
	public Claims getClaims(String token) {
		Claims claims = Jwts.parserBuilder()
				.setSigningKey(SECRET_KEY)
				.build()
				.parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
				.getBody();
		return claims;
	}

	@Override
	public String getUsername(String token) {
		return getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws JsonMappingException, JsonProcessingException {
		//traemos los roles del token, llamando la clave que le colocamos en el claims al generar el token
		Object roles = getClaims(token).get("authorities");
		//convertimos el json con los roles que bienen en el claims a un collection de tipo SimpleGrantedAuthority
		Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper().addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthoritiesMixin.class).readValue(roles.toString(), SimpleGrantedAuthority[].class));
		return authorities;
	}

}
