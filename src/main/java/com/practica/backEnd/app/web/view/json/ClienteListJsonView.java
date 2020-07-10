package com.practica.backEnd.app.web.view.json;

import java.util.Map;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

@Component("cliente/menu")
public class ClienteListJsonView extends MappingJackson2JsonView{

	@Override
	protected Object filterModel(Map<String, Object> model) {
		model.remove("titulo");
		return super.filterModel(model);
	}
	
}
