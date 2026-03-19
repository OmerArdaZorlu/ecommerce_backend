package com.ecommerce.main.admin;

import com.ecommerce.main.audit.AuditEventType;
import com.ecommerce.main.audit.AuditLog;
import com.ecommerce.main.audit.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AuditLogRepository auditLogRepository;

    @GetMapping("/audit-logs")
    public ResponseEntity<Page<AuditLog>> getAll(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(auditLogRepository.findAll(pageable));
    }

    @GetMapping("/audit-logs/user/{email}")
    public ResponseEntity<Page<AuditLog>> getByUser(
            @PathVariable String email,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(auditLogRepository.findByUserEmail(email, pageable));
    }

    @GetMapping("/audit-logs/events/{type}")
    public ResponseEntity<Page<AuditLog>> getByEventType(
            @PathVariable AuditEventType type,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(auditLogRepository.findByEventType(type, pageable));
    }
}
