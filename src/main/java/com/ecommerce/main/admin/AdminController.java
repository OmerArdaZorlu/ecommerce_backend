package com.ecommerce.main.admin;

import com.ecommerce.main.audit.AuditEventType;
import com.ecommerce.main.audit.AuditLog;
import com.ecommerce.main.audit.AuditLogRepository;
import com.ecommerce.main.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminController {

    private final AdminService adminService;
    private final AuditLogRepository auditLogRepository;

    // ── Analytics ────────────────────────────────────────────────────────────

    @GetMapping("/analytics")
    public ResponseEntity<AdminAnalyticsResponse> getAnalytics() {
        return ResponseEntity.ok(adminService.getPlatformAnalytics());
    }

    // ── User Management ──────────────────────────────────────────────────────

    @GetMapping("/users")
    public ResponseEntity<Page<UserResponse>> listUsers(
            @RequestParam(required = false) Role role,
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(adminService.listUsers(role, keyword, pageable));
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<UserResponse> getUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.getUserById(id));
    }

    @PatchMapping("/users/{id}/suspend")
    public ResponseEntity<UserResponse> suspendUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.suspendUser(id));
    }

    @PatchMapping("/users/{id}/unsuspend")
    public ResponseEntity<UserResponse> unsuspendUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.unsuspendUser(id));
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        adminService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/users/{id}/role")
    public ResponseEntity<UserResponse> changeRole(
            @PathVariable Long id,
            @RequestParam Role role) {
        return ResponseEntity.ok(adminService.changeRole(id, role));
    }

    // ── Platform Settings ────────────────────────────────────────────────────

    @GetMapping("/settings")
    public ResponseEntity<PlatformSettings> getSettings() {
        return ResponseEntity.ok(adminService.getSettings());
    }

    @PutMapping("/settings")
    public ResponseEntity<PlatformSettings> updateSettings(@RequestBody PlatformSettings settings) {
        return ResponseEntity.ok(adminService.updateSettings(settings));
    }

    // ── Audit Logs ───────────────────────────────────────────────────────────

    @GetMapping("/audit-logs")
    public ResponseEntity<Page<AuditLog>> getAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(auditLogRepository.findAll(pageable));
    }

    @GetMapping("/audit-logs/user/{email}")
    public ResponseEntity<Page<AuditLog>> getAuditLogsByUser(
            @PathVariable String email,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(auditLogRepository.findByUserEmail(email, pageable));
    }

    @GetMapping("/audit-logs/events/{type}")
    public ResponseEntity<Page<AuditLog>> getAuditLogsByEventType(
            @PathVariable AuditEventType type,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(auditLogRepository.findByEventType(type, pageable));
    }
}
