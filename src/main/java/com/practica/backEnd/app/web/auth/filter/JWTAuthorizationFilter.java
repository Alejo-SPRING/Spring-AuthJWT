package com.practica.backEnd.app.web.auth.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practica.backEnd.app.web.auth.SimpleGrantedAuthoritiesMixin;
import com.practica.backEnd.app.web.auth.services.IJWTService;
import com.practica.backEnd.app.web.auth.services.JWTServiceImpl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter{

	private IJWTService jwtService;
	
	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, IJWTService jwtService) {
		super(authenticationManager);
		this.jwtService = jwtService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//traemos el parametro Authorization de la cavezera del request
		String header = request.getHeader("Authorization");
		//validamos si no bienen el parametro Authorization o si el header no bienen con la nomenclatura inicial de: "Bearer "
		if(header == null || !header.startsWith(JWTServiceImpl.TOKEN_PREFIX)) {
			//si se cumple la condición se cierra el filtro y termina la ejecución del metodo
			chain.doFilter(request, response);
			return;
		}
		UsernamePasswordAuthenticationToken authToken = null;
		//si el token es valido ingresa
		if(jwtService.validate(header)) {
			//traemos el subject del token o el id principal del usuario
			String username = jwtService.getUsername(header);
			Collection<? extends GrantedAuthority> roles = jwtService.getRoles(header);
			//encapsulamos los datos del usuario en un token del server
			authToken = new UsernamePasswordAuthenticationToken(username, null, roles);
			//authenticamos al usuario en el contexto de springSecurity (hacemos el login) pero solo en el request, por que no manejamos sesiones (logeamos el usuario en springSecurity)
			SecurityContextHolder.getContext().setAuthentication(authToken);
			chain.doFilter(request, response);
		}
	}
	
}
