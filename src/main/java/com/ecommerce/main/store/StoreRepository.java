package com.ecommerce.main.store;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface StoreRepository extends JpaRepository<Store, Long> {
    List<Store> findByOwnerEmail(String email);
    Page<Store> findByStatus(StoreStatus status, Pageable pageable);
    List<Store> findByOwnerEmailAndStatus(String email, StoreStatus status);
}
