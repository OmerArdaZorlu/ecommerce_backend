package com.ecommerce.main.email;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

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
        message.setSubject("Email Verification - DataPulse");
        message.setText(
            "Merhaba,\n\n" +
            "Dogrulama kodunuz: " + code + "\n\n" +
            "Bu kod 15 dakika gecerlidir.\n\n" +
            "DataPulse Team"
        );

        mailSender.send(message);
    }

    public void sendPasswordResetEmail(String toEmail, String code) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("Password Reset - DataPulse");
        message.setText(
            "Merhaba,\n\n" +
            "Sifre sifirlama kodunuz: " + code + "\n\n" +
            "Bu kod 15 dakika gecerlidir.\n\n" +
            "DataPulse Team"
        );

        mailSender.send(message);
    }
}
