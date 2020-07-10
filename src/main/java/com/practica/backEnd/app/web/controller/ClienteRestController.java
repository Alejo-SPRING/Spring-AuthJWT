package com.practica.backEnd.app.web.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.practica.backEnd.app.web.model.entity.UsuarioHasVenta;
import com.practica.backEnd.app.web.model.services.IUsuarioHasVentaService;

@RestController
@RequestMapping("/api")
public class ClienteRestController {

	@Autowired
	private IUsuarioHasVentaService usuarioHasVentaDao;
	
	@GetMapping("/findVentas")
	public List<UsuarioHasVenta> findVentas() {
		return usuarioHasVentaDao.findAllProducto();
	}
	
}
