package com.practica.backEnd.app.web.model.entity;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.springframework.boot.jackson.JsonComponent;
import org.springframework.format.annotation.DateTimeFormat;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;

@Entity
@Table(name = "ventas")
public class Venta implements Serializable {

	private static final long serialVersionUID = 1L;
	@Id
	@Column(name = "venta_id")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer ventaId;
	@Column(name = "fecha_vena")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	@NotNull
	@JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
	private Date fechaVenta;
	@Column(name = "venta_total")
	@NotNull
	private int ventaTotal;
	@Column(name = "venta_pago")
	@NotEmpty
	@Size(max = 45)
	private String ventaPago;
	@OneToMany(mappedBy = "ventaId", fetch = FetchType.LAZY)
	@JsonBackReference
	private List<UsuarioHasVenta> listVentas;
	@OneToMany(mappedBy = "ventaId")
	@JsonManagedReference
	private List<VentaHasProducto> listProductos;

	public List<VentaHasProducto> getListProductos() {
		return listProductos;
	}

	public void setListProductos(List<VentaHasProducto> listProductos) {
		this.listProductos = listProductos;
	}

	public List<UsuarioHasVenta> getListVentas() {
		return listVentas;
	}

	public void setListVentas(List<UsuarioHasVenta> listVentas) {
		this.listVentas = listVentas;
	}

	public Integer getVentaId() {
		return ventaId;
	}

	public void setVentaId(Integer ventaId) {
		this.ventaId = ventaId;
	}

	public Date getFechaVenta() {
		return fechaVenta;
	}

	public void setFechaVenta(Date fechaVenta) {
		this.fechaVenta = fechaVenta;
	}

	public int getVentaTotal() {
		return ventaTotal;
	}

	public void setVentaTotal(int ventaTotal) {
		this.ventaTotal = ventaTotal;
	}

	public String getVentaPago() {
		return ventaPago;
	}

	public void setVentaPago(String ventaPago) {
		this.ventaPago = ventaPago;
	}

}
