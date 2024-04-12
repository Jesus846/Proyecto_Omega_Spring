package com.gestion.empleados.repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.gestion.empleados.models.ProductoModels;

public interface ProductoRepository extends JpaRepository<ProductoModels, Long> {
    @Query("SELECT p FROM ProductoModels p WHERE"
            + " CONCAT(p.id, p.nombre, p.marca, p.hechoEn, p.precio) "
            + " LIKE %?1%")
    public Iterable<ProductoModels> findAll(String palabraClave);
}