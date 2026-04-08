package com.ecommerce.main.order;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface OrderItemRepository extends JpaRepository<OrderItem, Long> {
    List<OrderItem> findByOrderId(Long orderId);

    @Query("SELECT oi.product.id, oi.product.name, SUM(oi.quantity) as totalQty, SUM(oi.quantity * oi.unitPrice) as revenue " +
           "FROM OrderItem oi WHERE oi.order.store.id = :storeId " +
           "GROUP BY oi.product.id, oi.product.name ORDER BY revenue DESC")
    List<Object[]> findTopProductsByStoreRevenue(@Param("storeId") Long storeId);
}
