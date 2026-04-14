package com.ecommerce.main.cart;

import com.ecommerce.main.crypto.BlockchainVerificationService;
import com.ecommerce.main.crypto.CryptoVerificationResult;
import com.ecommerce.main.order.*;
import com.ecommerce.main.product.Product;
import com.ecommerce.main.product.ProductRepository;
import com.ecommerce.main.user.User;
import com.ecommerce.main.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CartService {

    private final CartRepository cartRepository;
    private final ProductRepository productRepository;
    private final UserRepository userRepository;
    private final OrderRepository orderRepository;
    private final BlockchainVerificationService blockchainVerificationService;

    /** Mevcut sepeti getir ya da boş sepet döndür */
    @Transactional
    public CartResponse getOrCreateCart(String email) {
        Cart cart = cartRepository.findByUserEmail(email)
                .orElseGet(() -> {
                    User user = findUser(email);
                    return cartRepository.save(Cart.builder().user(user).build());
                });
        return CartResponse.from(cart);
    }

    /** Ürün ekle ya da miktarı artır */
    @Transactional
    public CartResponse addItem(String email, CartItemRequest request) {
        Cart cart = getOrCreateCartEntity(email);
        Product product = findProduct(request.getProductId());

        // Tüm ürünler aynı store'dan olmalı
        if (!cart.getItems().isEmpty()) {
            Long existingStoreId = cart.getItems().get(0).getProduct().getStore().getId();
            if (!product.getStore().getId().equals(existingStoreId)) {
                throw new IllegalStateException(
                        "Cart can only contain products from one store. Clear the cart first.");
            }
        }

        if (product.getStockQuantity() < request.getQuantity()) {
            throw new IllegalStateException("Insufficient stock for: " + product.getName());
        }

        Optional<CartItem> existing = cart.getItems().stream()
                .filter(i -> i.getProduct().getId().equals(product.getId()))
                .findFirst();

        if (existing.isPresent()) {
            existing.get().setQuantity(existing.get().getQuantity() + request.getQuantity());
        } else {
            CartItem item = CartItem.builder()
                    .cart(cart)
                    .product(product)
                    .quantity(request.getQuantity())
                    .build();
            cart.getItems().add(item);
        }

        return CartResponse.from(cartRepository.save(cart));
    }

    /** Ürün miktarını güncelle */
    @Transactional
    public CartResponse updateItem(String email, Long cartItemId, int quantity) {
        Cart cart = getOrCreateCartEntity(email);
        CartItem item = findItem(cart, cartItemId);

        if (quantity <= 0) {
            cart.getItems().remove(item);
        } else {
            if (item.getProduct().getStockQuantity() < quantity) {
                throw new IllegalStateException("Insufficient stock for: " + item.getProduct().getName());
            }
            item.setQuantity(quantity);
        }

        return CartResponse.from(cartRepository.save(cart));
    }

    /** Sepetten ürün kaldır */
    @Transactional
    public CartResponse removeItem(String email, Long cartItemId) {
        Cart cart = getOrCreateCartEntity(email);
        cart.getItems().remove(findItem(cart, cartItemId));
        return CartResponse.from(cartRepository.save(cart));
    }

    /** Sepeti temizle */
    @Transactional
    public void clearCart(String email) {
        Cart cart = getOrCreateCartEntity(email);
        cart.getItems().clear();
        cartRepository.save(cart);
    }

    /** Checkout: sepeti siparişe dönüştür */
    @Transactional
    public OrderResponse checkout(String email, String paymentMethod, String shippingAddress,
                                  String txHash, int chainId) {
        Cart cart = getOrCreateCartEntity(email);

        if (cart.getItems().isEmpty()) {
            throw new IllegalStateException("Cart is empty");
        }

        User user = findUser(email);
        var store = cart.getItems().get(0).getProduct().getStore();

        // ─── Stok kontrolü + toplam hesaplama ────────────────────────────────
        double total = 0.0;
        for (CartItem cartItem : cart.getItems()) {
            if (cartItem.getProduct().getStockQuantity() < cartItem.getQuantity()) {
                throw new IllegalStateException(
                    "Insufficient stock for: " + cartItem.getProduct().getName());
            }
            total += cartItem.getQuantity() * cartItem.getProduct().getUnitPrice();
        }

        // ─── Kripto ödeme doğrulaması ─────────────────────────────────────────
        OrderStatus initialStatus = OrderStatus.PENDING;
        if (paymentMethod.startsWith("CRYPTO_WALLET")) {
            if (txHash == null || txHash.isBlank()) {
                throw new IllegalStateException(
                    "Kripto ödeme için blockchain işlem hash'i (txHash) gereklidir.");
            }
            CryptoVerificationResult result =
                blockchainVerificationService.verify(txHash, chainId, total);
            if (!result.isSuccess()) {
                throw new IllegalStateException(result.getMessage());
            }
            initialStatus = OrderStatus.CONFIRMED;
        }

        // ─── Sipariş oluştur ──────────────────────────────────────────────────
        Order order = Order.builder()
                .user(user)
                .store(store)
                .paymentMethod(paymentMethod)
                .shippingAddress(shippingAddress)
                .status(initialStatus)
                .grandTotal(total)
                .txHash(txHash)
                .build();

        for (CartItem cartItem : cart.getItems()) {
            Product product = cartItem.getProduct();
            product.setStockQuantity(product.getStockQuantity() - cartItem.getQuantity());
            productRepository.save(product);

            OrderItem orderItem = OrderItem.builder()
                    .order(order)
                    .product(product)
                    .quantity(cartItem.getQuantity())
                    .unitPrice(product.getUnitPrice())
                    .build();
            order.getItems().add(orderItem);
        }

        Order saved = orderRepository.save(order);

        // Sepeti temizle
        cart.getItems().clear();
        cartRepository.save(cart);

        return OrderResponse.from(saved);
    }

    private Cart getOrCreateCartEntity(String email) {
        return cartRepository.findByUserEmail(email)
                .orElseGet(() -> {
                    User user = findUser(email);
                    return cartRepository.save(Cart.builder().user(user).build());
                });
    }

    private CartItem findItem(Cart cart, Long cartItemId) {
        return cart.getItems().stream()
                .filter(i -> i.getId().equals(cartItemId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Cart item not found: " + cartItemId));
    }

    private User findUser(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + email));
    }

    private Product findProduct(Long id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Product not found: " + id));
    }
}
