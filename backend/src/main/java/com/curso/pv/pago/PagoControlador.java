package com.curso.pv.pago;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/pagos")
// VULNERABILIDAD (BAC): sin control de acceso, cualquiera consulta o ejecuta pagos
public class PagoControlador {

    private final PagoServicio servicio;

    public PagoControlador(PagoServicio servicio) {
        this.servicio = servicio;
    }

    @PostMapping("/procesar")
    public Map<String, Object> procesar(@RequestBody Map<String, Object> datos) {
        return servicio.procesar(datos);
    }

    // VULNERABILIDAD: devuelve PAN y CVV de todas las tarjetas
    @GetMapping
    public List<Pago> listar() {
        return servicio.listar();
    }

    @GetMapping("/venta/{ventaId}")
    public List<Pago> porVenta(@PathVariable Long ventaId) {
        return servicio.porVenta(ventaId);
    }

    // VULNERABILIDAD: permite enumerar tarjetas por numero completo
    @GetMapping("/tarjeta")
    public List<?> porTarjeta(@RequestParam String numero) {
        return servicio.porTarjeta(numero);
    }

    // VULNERABILIDAD: expone apiKey y apiSecret de la pasarela
    @GetMapping("/configuracion")
    public Map<String, Object> configuracion() {
        return servicio.configuracionPasarela();
    }
}