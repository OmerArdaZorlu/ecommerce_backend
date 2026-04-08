package com.ecommerce.main.email;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.mail.from}")
    private String fromEmail;

    @Value("${app.base-url}")
    private String baseUrl;

    public void sendVerificationEmail(String toEmail, String code) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("Email Verification - Ecom");
        message.setText(
            "Merhaba,\n\n" +
            "Dogrulama kodunuz: " + code + "\n\n" +
            "Bu kod 15 dakika gecerlidir.\n\n" +
            "Ecom"
        );

        mailSender.send(message);
    }

    public void sendPasswordResetEmail(String toEmail, String code) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("Password Reset - Ecom");
        message.setText(
            "Merhaba,\n\n" +
            "Sifre sifirlama kodunuz: " + code + "\n\n" +
            "Bu kod 15 dakika gecerlidir.\n\n" +
            "Ecom Team"
        );

        mailSender.send(message);
    }
}
