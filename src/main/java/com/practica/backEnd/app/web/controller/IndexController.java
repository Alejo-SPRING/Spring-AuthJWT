package com.practica.backEnd.app.web.controller;

import java.security.Principal;
import java.util.List;
import java.util.Locale;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.annotation.RequestScope;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.practica.backEnd.app.web.model.entity.UsuarioHasRol;
import com.practica.backEnd.app.web.model.entity.UsuarioLogin;
import com.practica.backEnd.app.web.model.services.IUsuarioHasRolService;
import com.practica.backEnd.app.web.model.services.IUsuarioLoginService;

@Controller
public class IndexController {

	@Autowired
	private IUsuarioLoginService usuarioLoginDAO;
	private UsuarioLogin usuarioLoginDTO = new UsuarioLogin();
	private UsuarioHasRol rol = new UsuarioHasRol();
	@Autowired
	private IUsuarioHasRolService rolDao;
	@Autowired
	private BCryptPasswordEncoder encode;
	@Autowired
	private MessageSource messageSource;

	@GetMapping("/restApi")
	public @ResponseBody List<UsuarioLogin> findUsuarios() {
		return usuarioLoginDAO.findAllProducto();
	}

	@GetMapping("/")
	public @ResponseBody String index() {
		//return "redirect:/cliente/inicio";
		return "logeado";
	}

	/**
	 * Traduccion desde el back con mensaje de error de contraseña o correo
	 * @param error
	 * @param logout
	 * @param lang
	 * @param model
	 * @param principal
	 * @param redirect
	 * @param locale
	 * @return
	 */
	@GetMapping("/springLogin2")
	public String springLogin(@RequestParam(value = "error", required = false) String error,
			@RequestParam(name = "logout", required = false) String logout, Model model, Principal principal,
			RedirectAttributes redirect, Locale locale) {
		if (principal != null) {
			redirect.addFlashAttribute("mensaje", "Ya iniciaste sesión!");
			return "redirect:/cliente/inicio";
		}
		if (error != null) {
			model.addAttribute("mensaje", messageSource.getMessage("text.error.session", null, locale));
		}
		if (logout != null) {
			model.addAttribute("mensaje", "Sessión cerrada!");
		}
		return "login";
	}

	@PostMapping("/registrar")
	public String registrar(@Valid UsuarioLogin usuarioLogin, BindingResult result, RedirectAttributes redirect,
			Model model) {
		if (result.hasErrors()) {
			model.addAttribute("titulo", "RegistrarValid");
			return "registrar";
		} else {
			usuarioLogin.setUsuarioPass(encode.encode(usuarioLogin.getUsuarioPass()));
			rol.setEstado(true);
			rol.setRol("ROLE_ADMIN");
			rol.setUsuarioLogin(usuarioLogin);
			rolDao.create(rol);
			redirect.addFlashAttribute("mensaje", "success(\"Registrado, bienvenido!\");");
		}
		return "redirect:/springLogin2";
	}

	@GetMapping("/registrar")
	public String registrar(Model model) {
		model.addAttribute("titulo", "Registrar");
		model.addAttribute("usuarioLogin", usuarioLoginDTO);
		return "registrar";
	}

}
