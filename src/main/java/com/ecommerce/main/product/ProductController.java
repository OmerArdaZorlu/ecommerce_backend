package com.ecommerce.main.product;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;

    @GetMapping
    public ResponseEntity<Page<Product>> getAll(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "id") String sortBy) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(sortBy));
        return ResponseEntity.ok(productService.getAll(pageable));
    }

    @GetMapping("/search")
    public ResponseEntity<Page<Product>> search(
            @RequestParam String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size);
        return ResponseEntity.ok(productService.search(keyword, pageable));
    }

    @GetMapping("/store/{storeId}")
    public ResponseEntity<Page<Product>> getByStore(
            @PathVariable Long storeId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size);
        return ResponseEntity.ok(productService.getByStore(storeId, pageable));
    }

    @GetMapping("/category/{categoryId}")
    public ResponseEntity<Page<Product>> getByCategory(
            @PathVariable Long categoryId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size);
        return ResponseEntity.ok(productService.getByCategory(categoryId, pageable));
    }

    @GetMapping("/store/{storeId}/low-stock")
    @PreAuthorize("hasAnyAuthority('ROLE_CORPORATE', 'ROLE_ADMIN')")
    public ResponseEntity<List<Product>> getLowStock(
            @PathVariable Long storeId,
            @RequestParam(defaultValue = "10") int threshold) {
        return ResponseEntity.ok(productService.getLowStock(storeId, threshold));
    }

    @GetMapping("/{id}")
    public ResponseEntity<Product> getById(@PathVariable Long id) {
        return ResponseEntity.ok(productService.getById(id));
    }

    @PostMapping("/store/{storeId}")
    @PreAuthorize("hasAnyAuthority('ROLE_CORPORATE', 'ROLE_ADMIN')")
    public ResponseEntity<Product> create(@PathVariable Long storeId,
                                          @Valid @RequestBody ProductRequest request,
                                          Authentication auth) {
        return ResponseEntity.ok(productService.create(storeId, auth.getName(), request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_CORPORATE', 'ROLE_ADMIN')")
    public ResponseEntity<Product> update(@PathVariable Long id,
                                          @Valid @RequestBody ProductRequest request,
                                          Authentication auth) {
        return ResponseEntity.ok(productService.update(id, auth.getName(), request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_CORPORATE', 'ROLE_ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable Long id, Authentication auth) {
        productService.delete(id, auth.getName());
        return ResponseEntity.noContent().build();
    }
}
