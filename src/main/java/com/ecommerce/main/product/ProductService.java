package com.ecommerce.main.product;

import com.ecommerce.main.category.Category;
import com.ecommerce.main.category.CategoryRepository;
import com.ecommerce.main.store.Store;
import com.ecommerce.main.store.StoreRepository;
import com.ecommerce.main.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ProductService {

    private final ProductRepository productRepository;
    private final StoreRepository storeRepository;
    private final CategoryRepository categoryRepository;
    private final UserRepository userRepository;

    public Page<Product> getAll(Pageable pageable) {
        return productRepository.findByActiveTrue(pageable);
    }

    public Page<Product> getByStore(Long storeId, Pageable pageable) {
        return productRepository.findByStoreIdAndActiveTrue(storeId, pageable);
    }

    public Page<Product> getByCategory(Long categoryId, Pageable pageable) {
        return productRepository.findByCategoryIdAndActiveTrue(categoryId, pageable);
    }

    public Page<Product> search(String keyword, Pageable pageable) {
        return productRepository.search(keyword, pageable);
    }

    public Product getById(Long id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found: " + id));
    }

    public List<Product> getLowStock(Long storeId, int threshold) {
        return productRepository.findByStoreIdAndStockQuantityLessThan(storeId, threshold);
    }

    public Product create(Long storeId, String requestorEmail, ProductRequest request) {
        Store store = storeRepository.findById(storeId)
                .orElseThrow(() -> new RuntimeException("Store not found: " + storeId));
        assertStoreOwner(store, requestorEmail);

        Category category = null;
        if (request.getCategoryId() != null) {
            category = categoryRepository.findById(request.getCategoryId())
                    .orElseThrow(() -> new RuntimeException("Category not found"));
        }

        Product product = Product.builder()
                .store(store)
                .category(category)
                .sku(request.getSku())
                .name(request.getName())
                .description(request.getDescription())
                .unitPrice(request.getUnitPrice())
                .stockQuantity(request.getStockQuantity())
                .productImportance(request.getProductImportance())
                .build();
        return productRepository.save(product);
    }

    public Product update(Long id, String requestorEmail, ProductRequest request) {
        Product product = getById(id);
        assertStoreOwner(product.getStore(), requestorEmail);

        product.setName(request.getName());
        product.setSku(request.getSku());
        product.setDescription(request.getDescription());
        product.setUnitPrice(request.getUnitPrice());
        product.setStockQuantity(request.getStockQuantity());
        product.setProductImportance(request.getProductImportance());

        if (request.getCategoryId() != null) {
            Category category = categoryRepository.findById(request.getCategoryId())
                    .orElseThrow(() -> new RuntimeException("Category not found"));
            product.setCategory(category);
        }
        return productRepository.save(product);
    }

    public void delete(Long id, String requestorEmail) {
        Product product = getById(id);
        assertStoreOwner(product.getStore(), requestorEmail);
        product.setActive(false);
        productRepository.save(product);
    }

    private void assertStoreOwner(Store store, String requestorEmail) {
        boolean isAdmin = userRepository.findByEmail(requestorEmail)
                .map(u -> u.getRoleType().name().equals("ADMIN"))
                .orElse(false);
        if (!isAdmin && !store.getOwner().getEmail().equals(requestorEmail)) {
            throw new RuntimeException("Access denied");
        }
    }
}
