# Threat Model — Linux AI System Administrator Agent (Beta)

Phiên bản: 0.1 (bản đầu — Ngày 1)
Người phụ trách: C (Safety & Remediation)
Cập nhật lần cuối: 22/10/2026

> Tài liệu này liệt kê mức rủi ro của từng tool/action, các hành động bị cấm
> trong beta, giả định an toàn và giới hạn đã biết. Đây là cơ sở để
> PolicyEngine (`src/linux_admin/control/policy_engine.py`) ra quyết định
> allow / deny / approval_required.

---

## 1. Giả định an toàn (fail-closed)

1. Mọi action thay đổi hệ thống **phải** đi qua `Executor`. Tool không được
   gọi `subprocess` ghi/thay đổi hệ thống và bỏ qua lớp này.
2. `PolicyEngine` **độc lập với LLM**. LLM không được tự cấp quyền; mức rủi ro
   và quyết định allow/deny lấy từ `config/policy.yaml`.
3. Lỗi cấu hình, lỗi đọc policy, lỗi audit → **deny** (fail-closed).
4. Action không khai báo trong `config/policy.yaml` → dùng
   `policy.default_decision` (mặc định `deny`).
5. Beta chạy dưới quyền user thường; **không chạy toàn bộ agent dưới root**.

---

## 2. Phân loại mức rủi ro

| Mức | Ý nghĩa | Hành vi mặc định |
|---|---|---|
| `read_only` | Chỉ đọc dữ liệu hệ thống | Được phép, không cần approval |
| `low` | Ghi nhẹ, có thể hoàn tác, phạm vi hẹp | Cần approval trong beta |
| `medium` | Thay đổi service/tiến trình, ảnh hưởng tạm thời | Cần approval + allowlist |
| `high` | Xóa dữ liệu, thay đổi cấu hình hệ thống, leo thang đặc quyền | **Bị cấm trong beta** |

---

## 3. Bảng mức rủi ro từng tool/action

| Action / Tool | Nhóm | Mức rủi ro | `allowed` | `requires_approval` | Ghi chú |
|---|---|---|---|---|---|
| `inspect_system` (`get_system_overview`, `get_disk_usage`, `list_top_processes`) | System Observer | `read_only` | true | false | Chỉ đọc qua psutil / /proc |
| `read_service_logs` (`get_failed_services`, `get_service_logs`, `get_recent_errors`) | Logs & Diagnosis | `read_only` | true | false | Giới hạn số dòng/thời gian |
| `get_service_status` | Service Manager | `read_only` | true | false | `systemctl is-active` |
| Network diagnostics (`get_network_state`, `check_tcp_connectivity`, `check_http_endpoint`) | Network | `read_only` | true | false | Giới hạn host/port/timeout |
| `inspect_security_posture`, `check_action_policy` | Security & Policy | `read_only` | true | false | Kiểm tra quyền, phân loại action |
| `restart_service` | Service Manager | `medium` | **false** (beta) | true | Chỉ service trong allowlist; beta chặn thật (`allowed: false`) |
| `clean_package_cache` | Remediation | `low` | **false** (beta) | true | Chưa bật trong beta |
| `delete_files` | Remediation | `high` | **false** | true | **Cấm tuyệt đối trong beta** |
| `shell` / `sudo` / `su` | Privilege escalation | `high` | **false** | — | **Cấm tuyệt đối**; `allow_privilege_escalation: false` |
| `format_disk` / `modify_system_file` | System-level | `high` | **false** | — | **Cấm tuyệt đối** |
| Action không khai báo | — | — | — | — | Dùng `default_decision: deny` |

> Ghi chú: cột `allowed` phản ánh **cấu hình beta hiện tại** trong
> `config/policy.yaml`. Khi sang Ngày 6–7 demo restart thật, nhóm trưởng
> đổi `restart_service.allowed: true` — logic code không cần sửa.

---

## 4. Hành động bị cấm tuyệt đối trong beta

Các hành động sau **không được phép thực thi** trong bất kỳ tình huống nào
của beta, kể cả khi người dùng yêu cầu:

1. **Leo thang đặc quyền**: `sudo`, `su`, `privilege_escalation`.
   → `policy.allow_privilege_escalation: false`.
2. **Xóa dữ liệu**: `delete_files`, `rm`, `rm -rf`, xóa log người dùng.
3. **Thay đổi cấu hình hệ thống**: `modify_system_file`, sửa `/etc/*`,
   sửa unit systemd.
4. **Định dạng / ghi đè ổ đĩa**: `format_disk`, `dd`, `mkfs`.
5. **Shell tổng quát**: thực thi chuỗi lệnh tự do từ LLM.
6. **Dọn dẹp tự động**: `clean_package_cache` — beta chỉ chẩn đoán, không
   tự xóa.
7. **Restart service ngoài allowlist** hoặc ngoài
   `test_service_for_restart`.
8. **Mọi action không khai báo** trong `config/policy.yaml` → bị `deny`
   qua `default_decision`.

---

## 5. Giới hạn beta (đã biết)

- Chỉ chạy trên **một Ubuntu VM**, không hỗ trợ multi-host.
- Chỉ **một LLM** qua API, có `FakeLLMClient` fallback.
- Chỉ **một service thử nghiệm** (`test-app`) được phép restart thật.
- Không có dashboard, không auto-cleanup, không multi-agent.
- Audit lưu SQLite cục bộ (`audit.db`), chưa có log rotation.
- Approval lưu trong bộ nhớ (`ApprovalManager`), chưa persist.
- Không hỗ trợ Kubernetes, kernel module, quản trị production tự động.

---

## 6. Đối chiếu với OWASP

- **Least privilege**: beta chạy user thường; policy chặn leo thang.
- **Tách decision / execution**: `PolicyEngine` quyết định, `Executor`
  thực thi — LLM không tự cấp quyền.
- **Human approval**: action `medium`/`low` cần approval gắn đúng
  `(action, target, params)` + TTL.
- **Audit**: mọi `policy_decision`, `approval_missing`, `action_start`,
  `action_result` đều ghi `audit.db`.
- **Verification**: không tin exit code; kiểm tra hậu điều kiện bằng
  `health_checks.py`.
- **Fail-closed**: mọi lỗi cấu hình/audit/policy → deny.

---

## 7. Việc cần cập nhật (Ngày 4–9)

- [ ] Bổ sung mối đe dọa cụ thể theo từng kịch bản (service failure,
      unreachable endpoint, disk pressure).
- [ ] Ghi rõ quyền hệ thống cần cấp (nếu có) cho `test-app`.
- [ ] Đối chiếu với `docs/acceptance.md` khi chốt beta.

