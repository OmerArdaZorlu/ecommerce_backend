package com.ecommerce.main.admin;

import com.ecommerce.main.user.User;

import java.time.LocalDateTime;

public record UserResponse(
        Long id,
        String name,
        String email,
        String roleType,
        String provider,
        boolean verified,
        boolean twoFactorEnabled,
        int failedLoginAttempts,
        LocalDateTime lockedUntil,
        LocalDateTime createdAt
) {
    public static UserResponse from(User u) {
        return new UserResponse(
                u.getId(),
                u.getName(),
                u.getEmail(),
                u.getRoleType().name(),
                u.getProvider().name(),
                u.isVerified(),
                u.isTwoFactorEnabled(),
                u.getFailedLoginAttempts(),
                u.getLockedUntil(),
                u.getCreatedAt()
        );
    }
}
