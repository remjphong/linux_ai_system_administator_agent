# Safety and Operations Runbook

## 1. Quy tắc an toàn
- Fail-closed: Mọi lỗi cấu hình, audit đều dẫn đến từ chối.
- Không có `shell=True`, không tự ý nâng quyền.
- Mọi action thay đổi hệ thống phải qua `ControlledExecutor`.

## 2. Trạng thái Restart Service trong Beta
- Mặc định `restart_enabled: false` trong `services.yaml`.
- Action `restart_service` yêu cầu `allowed: true` (policy) và Approval.
- Chỉ service nằm trong `allowlist` mới được thao tác.

## 3. Cách phê duyệt
- Gọi `ApprovalManager.grant(action, target, params)`.
- Approval có hiệu lực 300s. Hết hạn phải xin lại.

## 4. Xử lý khi Verification thất bại
- Retry tối đa 2 lần (`handle_recovery_retry`).
- Hết retry → Dừng, ghi audit, báo "Cần can thiệp thủ công". Không tự chuyển sang action nguy hiểm.
