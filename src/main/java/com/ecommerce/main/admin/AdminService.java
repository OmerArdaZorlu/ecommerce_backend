package com.ecommerce.main.admin;

import com.ecommerce.main.order.OrderRepository;
import com.ecommerce.main.order.OrderStatus;
import com.ecommerce.main.product.ProductRepository;
import com.ecommerce.main.review.ReviewRepository;
import com.ecommerce.main.store.StoreRepository;
import com.ecommerce.main.store.StoreStatus;
import com.ecommerce.main.user.Role;
import com.ecommerce.main.user.User;
import com.ecommerce.main.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final StoreRepository storeRepository;
    private final OrderRepository orderRepository;
    private final ProductRepository productRepository;
    private final ReviewRepository reviewRepository;
    private final PlatformSettingsRepository settingsRepository;

    @Transactional(readOnly = true)
    public AdminAnalyticsResponse getPlatformAnalytics() {
        long totalUsers      = userRepository.count();
        long individualUsers = userRepository.countByRoleType(Role.INDIVIDUAL);
        long corporateUsers  = userRepository.countByRoleType(Role.CORPORATE);
        long totalStores     = storeRepository.count();
        long activeStores    = storeRepository.countByStatus(StoreStatus.OPEN);
        long pendingStores   = storeRepository.countByStatus(StoreStatus.PENDING);
        long totalOrders     = orderRepository.count();
        long pendingOrders   = orderRepository.countByStatus(OrderStatus.PENDING);
        long cancelledOrders = orderRepository.countByStatus(OrderStatus.CANCELLED);
        Double revenueRaw    = orderRepository.sumTotalRevenue();
        double totalRevenue  = revenueRaw != null ? revenueRaw : 0.0;
        long totalProducts   = productRepository.count();
        long totalReviews    = reviewRepository.count();

        List<AdminAnalyticsResponse.StoreComparisonEntry> storeComparison =
                storeRepository.storeRevenueComparison().stream()
                        .map(row -> new AdminAnalyticsResponse.StoreComparisonEntry(
                                ((Number) row[0]).longValue(),
                                (String) row[1],
                                ((Number) row[2]).longValue(),
                                ((Number) row[3]).doubleValue()
                        ))
                        .toList();

        return new AdminAnalyticsResponse(
                totalUsers, individualUsers, corporateUsers,
                totalStores, activeStores, pendingStores,
                totalOrders, pendingOrders, cancelledOrders,
                totalRevenue, totalProducts, totalReviews,
                storeComparison
        );
    }

    @Transactional(readOnly = true)
    public Page<UserResponse> listUsers(Role role, String keyword, Pageable pageable) {
        return userRepository.searchUsers(role, keyword, pageable).map(UserResponse::from);
    }

    @Transactional(readOnly = true)
    public UserResponse getUserById(Long id) {
        return UserResponse.from(findUser(id));
    }

    @Transactional
    public UserResponse suspendUser(Long id) {
        User user = findUser(id);
        user.setLockedUntil(java.time.LocalDateTime.now().plusYears(100));
        return UserResponse.from(userRepository.save(user));
    }

    @Transactional
    public UserResponse unsuspendUser(Long id) {
        User user = findUser(id);
        user.setLockedUntil(null);
        user.setFailedLoginAttempts(0);
        return UserResponse.from(userRepository.save(user));
    }

    @Transactional
    public void deleteUser(Long id) {
        userRepository.delete(findUser(id));
    }

    @Transactional
    public UserResponse changeRole(Long id, Role newRole) {
        User user = findUser(id);
        user.setRoleType(newRole);
        return UserResponse.from(userRepository.save(user));
    }

    @Transactional(readOnly = true)
    public PlatformSettings getSettings() {
        return settingsRepository.findById(1L).orElseGet(() ->
                settingsRepository.save(PlatformSettings.builder().id(1L).build()));
    }

    @Transactional
    public PlatformSettings updateSettings(PlatformSettings incoming) {
        incoming.setId(1L);
        return settingsRepository.save(incoming);
    }

    private User findUser(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + id));
    }
}
