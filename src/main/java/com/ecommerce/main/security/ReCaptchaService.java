package com.ecommerce.main.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class ReCaptchaService {

    @Value("${recaptcha.secret-key}")
    private String secretKey;

    private static final String VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    private final RestTemplate restTemplate = new RestTemplate();

    private static final double MIN_SCORE = 0.5;

    public void verify(String token) {
        String url = VERIFY_URL + "?secret=" + secretKey + "&response=" + token;

        @SuppressWarnings("unchecked")
        Map<String, Object> response = restTemplate.postForObject(url, null, Map.class);

        if (response == null || !Boolean.TRUE.equals(response.get("success"))) {
            throw new IllegalArgumentException("reCAPTCHA dogrulamasi basarisiz");
        }

        double score = ((Number) response.get("score")).doubleValue();
        if (score < MIN_SCORE) {
            throw new IllegalArgumentException("reCAPTCHA skoru yetersiz (bot aktivitesi tespit edildi)");
        }
    }
}
