package com.practica.backEnd.app.web.auth.filter;

import java.io.IOException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.practica.backEnd.app.web.auth.services.IJWTService;
import com.practica.backEnd.app.web.auth.services.JWTServiceImpl;
import com.practica.backEnd.app.web.model.entity.UsuarioLogin;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	
	//atributo para realizar el login con la clase: JpaUserDetailService, que se encarga de hacer la busqueda del usuario por el nombre o id
	private AuthenticationManager authenticationManager;
	//servicio donde estan los metodos para manejar los tokens
	private IJWTService jwtService;
	
	//se utiliza este objeto para poder utlizar la clase de: JpaUserDetailService
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, IJWTService jwtService) {
		this.authenticationManager = authenticationManager;
		this.jwtService = jwtService;
		//cambiar la ruta de login o el metodo
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
	}
	
	//metodo para hacer el login
	@SuppressWarnings("unused")
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		String username = obtainUsername(request);
		String password = obtainPassword(request);
		//si son null es porque los datos bienen en JSON
		if(username == null && password == null) {
			UsuarioLogin user = null;
				try {
					//convertimos el json que biene en el request a una clase UsuarioLogin
					user = new ObjectMapper().readValue(request.getInputStream(), UsuarioLogin.class);
					username = user.getUsuarioCorreo();
					password = user.getUsuarioPass();
				} catch (JsonParseException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (JsonMappingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		
		logger.info(username);
		logger.info(password);
		
		//contenedor de las credenciales, crea un token que se almacena en el servidor(es diferente al token de JWT)
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
		//llamamos al service: JpaUserDetailService para enviar las credenciales y hacer el login
		return authenticationManager.authenticate(authToken);
	}

	//metodo que creara el token si la authenticacion se ejecuta con exito
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		//creamos el token
		String token = jwtService.create(authResult);
		
		//agregamos el token al encavezado de la respuesta
		response.addHeader("Authorization", JWTServiceImpl.SECRET_KEY + token);
		
		//creamos unos parametros que se enviaran al cliente como respuesta
		Map<String, Object> body = new HashMap<>();
		body.put("token", token);
		body.put("user", (User) authResult.getPrincipal());
		body.put("mensaje", "Bienvenido");
		
		//escribimos en la respuesta el Map body y transformamos a JSON
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		//le colocamos el status ok, de que todo funciono
		response.setStatus(200);
		response.setContentType("application/json");
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		Map<String, Object> body = new HashMap<>();
		body.put("mensaje", "Error de authenticación: usuario o contraseña incorrecto!");
		body.put("error", failed.getMessage());
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(401);
		response.setContentType("application/json");
	}
	
}
