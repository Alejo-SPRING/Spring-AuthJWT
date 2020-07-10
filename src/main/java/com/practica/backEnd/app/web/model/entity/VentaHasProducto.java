package com.practica.backEnd.app.web.model.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;

@Entity
@Table(name = "venta_has_producto")
public class VentaHasProducto implements Serializable {

	private static final long serialVersionUID = 1L;
	@Id
	@Column(name = "idventa_has_producto")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer ventaHasProductoId;
	@JoinColumn(name = "venta_id", referencedColumnName = "venta_id")
	@ManyToOne
	@JsonBackReference
	private Venta ventaId;
	@JoinColumn(name = "producto_id", referencedColumnName = "producto_id")
	@ManyToOne
	@JsonManagedReference
	private Producto productoId;

	public Integer getVentaHasProductoId() {
		return ventaHasProductoId;
	}

	public void setVentaHasProductoId(Integer ventaHasProductoId) {
		this.ventaHasProductoId = ventaHasProductoId;
	}

	public Venta getVentaId() {
		return ventaId;
	}

	public void setVentaId(Venta ventaId) {
		this.ventaId = ventaId;
	}

	public Producto getProductoId() {
		return productoId;
	}

	public void setProductoId(Producto productoId) {
		this.productoId = productoId;
	}

}
