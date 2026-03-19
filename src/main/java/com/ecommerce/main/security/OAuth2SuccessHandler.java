package com.ecommerce.main.security;

import com.ecommerce.main.token.RefreshToken;
import com.ecommerce.main.token.RefreshTokenRepository;
import com.ecommerce.main.user.AuthProvider;
import com.ecommerce.main.user.Role;
import com.ecommerce.main.user.User;
import com.ecommerce.main.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.transaction.Transactional;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String googleId = oAuth2User.getAttribute("sub");

        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = User.builder()
                    .email(email)
                    .name(name)
                    .googleId(googleId)
                    .provider(AuthProvider.GOOGLE)
                    .roleType(Role.INDIVIDUAL)
                    .verified(true)
                    .build();
            return userRepository.save(newUser);
        });

        refreshTokenRepository.revokeAllByUserId(user.getId());

        String accessToken = jwtService.generateToken(user.getEmail());

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();
        refreshTokenRepository.save(refreshToken);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        String json = String.format(
                "{\"accessToken\":\"%s\",\"refreshToken\":\"%s\",\"email\":\"%s\",\"name\":\"%s\",\"role\":\"%s\"}",
                accessToken,
                refreshToken.getToken(),
                email,
                name,
                user.getRoleType()
        );
        response.getWriter().write(json);
    }
}
