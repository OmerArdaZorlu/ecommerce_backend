package com.ecommerce.main.order;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface OrderRepository extends JpaRepository<Order, Long> {
    Page<Order> findByUserEmail(String email, Pageable pageable);
    List<Order> findAllByUserEmail(String email);
    Page<Order> findByStoreId(Long storeId, Pageable pageable);
    Page<Order> findByStatus(OrderStatus status, Pageable pageable);
    Page<Order> findByUserEmailAndStatus(String email, OrderStatus status, Pageable pageable);
    Page<Order> findByStoreIdAndStatus(Long storeId, OrderStatus status, Pageable pageable);

    @Query("SELECT SUM(o.grandTotal) FROM Order o WHERE o.store.id = :storeId AND o.createdAt BETWEEN :from AND :to AND o.status != 'CANCELLED'")
    Double sumRevenueByStoreAndDateRange(@Param("storeId") Long storeId,
                                         @Param("from") LocalDateTime from,
                                         @Param("to") LocalDateTime to);
}
