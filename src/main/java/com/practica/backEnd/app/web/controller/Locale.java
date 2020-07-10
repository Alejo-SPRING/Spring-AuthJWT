package com.practica.backEnd.app.web.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class Locale {

	/**
	 * Metodo que obtiene el referer o la ultima url solicitada en la app
	 * @param request
	 * @return
	 */
	@GetMapping("/locale")
	public String locale(HttpServletRequest request) {
		String ultimaUrl = request.getHeader("referer");
		return "redirect:" + ultimaUrl;
	}
	
}
