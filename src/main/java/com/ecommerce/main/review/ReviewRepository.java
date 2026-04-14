package com.ecommerce.main.review;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ReviewRepository extends JpaRepository<Review, Long> {
    Page<Review> findByProductId(Long productId, Pageable pageable);
    Page<Review> findByUserEmail(String email, Pageable pageable);
    Page<Review> findByProductStoreId(Long storeId, Pageable pageable);
    Optional<Review> findByUserEmailAndProductId(String email, Long productId);
    boolean existsByUserEmailAndProductId(String email, Long productId);

    @Query("SELECT AVG(r.starRating) FROM Review r WHERE r.product.id = :productId")
    Double avgRatingByProduct(@Param("productId") Long productId);

    long countByProductId(Long productId);

    // Batch: avg rating + review count for a list of product IDs in one query
    @Query("SELECT r.product.id, AVG(r.starRating), COUNT(r) FROM Review r WHERE r.product.id IN :ids GROUP BY r.product.id")
    List<Object[]> avgAndCountByProductIds(@Param("ids") List<Long> ids);

    @Query("SELECT AVG(r.starRating) FROM Review r WHERE r.product.store.id = :storeId")
    Double avgRatingByStore(@Param("storeId") Long storeId);

    @Query("SELECT COUNT(r) FROM Review r WHERE r.product.store.id = :storeId")
    long countReviewsByStore(@Param("storeId") Long storeId);
}
