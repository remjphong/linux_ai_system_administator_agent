# Tool catalog — accepted functional baseline

Catalog này đối chiếu các adapter và `ToolSpec` đã triển khai tại commit `c05277ecd26512337ea29619321e4c99531fc9c0` (18/11/2026). `linux-admin --list-tools` in registry thực tế. Mỗi tool trả `ToolResult` gồm `tool_name`, `status`, `data`, `evidence` và có thể có `error`; lỗi permissions/unsupported/timeout không được thay bằng kết quả giả. **Tool có sẵn trong Registry không có nghĩa planner luôn gọi nó trong mọi prompt.** Các thông số dưới đây là public input; khi thiếu argument bắt buộc Registry từ chối.

## System observation — `src/linux_admin/tools/system.py`

| Tool | Tham số | Kết quả, ý nghĩa | Chế độ |
|---|---|---|---|
| `get_system_overview` | Không có | OS/platform, logical/physical CPU, CPU snapshot, RAM, swap, uptime, process count | Read-only |
| `get_disk_usage` | `path` (bắt buộc, 1–4096 ký tự); adapter có default `/` | Capacity/used/free/percentage cho path tồn tại | Read-only |
| `list_top_processes` | `limit` 1–50, default 5; `sort_by=cpu\|memory\|both`, default memory | PID/name/username/status, RSS/memory%, CPU sample; `both` trả `top_cpu` và `top_memory` | Read-only |
| `list_all_mounts` | Không có | Toàn bộ mount points qua `psutil.disk_partitions(all=True)`; usage có thể `null` | Read-only |
| `get_io_stats` | `sample_seconds` 0.1–5.0, default 1.0 | Device IOPS/throughput/utilization, CPU iowait%, per-process I/O hai snapshot | Read-only |

`get_io_stats` chỉ đo xấp xỉ trong cửa sổ thời gian ngắn: `_PROCESS_SCAN_LIMIT=256` mỗi snapshot; tối đa `_PROCESS_RESULT_LIMIT=10` process records sau sắp xếp theo tổng read/write byte delta, kèm PID, name, username, `read_bytes_delta`, `write_bytes_delta`, `read_bytes_per_sec`, `write_bytes_per_sec`. Có `process_io_sampled_count`, `process_io_inaccessible_count`, `process_io_counter_reset_count`, `process_io_supported`, `process_io_scan_limit`. So PID và process creation time để loại PID reuse; thiếu permission/unsupported/missing data/terminated PID bị bỏ qua. Counter delta âm của thiết bị/tiến trình bị loại, iowait delta không hợp lệ không tạo percentage. `process_io_supported=false` trong dữ liệu kết quả có thể chỉ nghĩa là **không có cặp mẫu hợp lệ**, không chứng minh toàn OS không hỗ trợ. Các metric này không chứng minh PID gây CPU iowait, bottleneck hay latency.

CPU/RAM percent và process rankings cũng chỉ là snapshot ngắn; cần lấy mẫu lặp lại có bối cảnh. Có thể không thu đủ record trên hệ thống nhiều PID/quyền hạn giới hạn.

## Systemd and logs — `tools/logs.py`, `tools/services.py`

| Tool | Tham số | Kết quả, giới hạn | Chế độ |
|---|---|---|---|
| `get_failed_services` | Không có | Tên unit systemd đang failed; phụ thuộc systemctl | Read-only |
| `get_service_status` | `service_name` bắt buộc | Load/active/substate và trạng thái unit; `systemctl` và unit name được kiểm tra | Read-only |
| `get_service_logs` | `service_name` bắt buộc; `lines` 1–200; `since_minutes` 1–1440 | Bounded journald lines cho service; phụ thuộc quyền xem journal | Read-only |
| `get_recent_errors` | `lines` 1–200; `since_minutes` 1–1440 | Journal ở error priority hoặc cao hơn | Read-only |
| `get_kernel_log` | `lines` 1–200; `since_minutes` 1–1440; `priority=emerg\|alert\|crit\|err\|warning` (default `err`) | `journalctl --dmesg` + priority/time/line filters; chỉ có OOM evidence nếu log hiện diện và nhìn thấy | Read-only |
| `check_auth_log` | `lines` 1–200; `since_minutes` 1–1440; `brute_force_threshold` 3–100 (default 10) | Login failures/successes, sudo events, source IP counts từ các entry auth được đọc | Read-only |
| `restart_service` | `service_name` bắt buộc | Yêu cầu `systemctl restart` qua protected workflow, sau đó hậu kiểm; **bị vô hiệu hóa theo default** | **State-changing, high-risk** |

Log reader dùng fixed commands + timeout; chưa chắc xem được kernel/auth journal nếu user không có quyền. Một log OOM không chứng minh áp lực RAM hiện tại, việc không thấy log không chứng minh “không có OOM”. Auth threshold là dấu hiệu nghi ngờ, **không chứng minh máy bị tấn công**. `get_service_status` không được tự đoán tên service từ port hoặc URL. Không chạy `restart_service` trong clean-install verification.

## Network — `tools/network.py`

| Tool | Tham số | Kết quả, giới hạn | Chế độ |
|---|---|---|---|
| `get_network_state` | Không có | Interface states, IP, speed, MTU qua psutil | Read-only |
| `check_tcp_connectivity` | `host`, `port` bắt buộc; `timeout_seconds` 0.1–5.0 | TCP handshake thành công, refused, timeout; probe có thể tạo outbound connection | Read-only probe |
| `check_http_endpoint` | `url` HTTP(S) bắt buộc; `timeout_seconds` 0.1–5.0 | HTTP status/health và reachability; không follow redirects, URL credentials/fragments bị từ chối, body read bounded | Read-only probe |
| `inspect_listening_port` | `port` bắt buộc, 1–65535 | Local LISTEN sockets tại port, address, PID và process name nếu quyền cho phép | Read-only |
| `list_listening_ports` | Không có | Snapshot tất cả local TCP LISTEN sockets; address/port/PID khi quan sát được | Read-only |

**Port 5432:** Có thể kiểm tra no listener, chỉ bind loopback hoặc non-loopback, TCP refused/timeout khi có endpoint chỉ định. Agent **không tự thực hiện quy trình đầy đủ ping/TCP/firewall/bind**; không có công cụ ping hay firewall state/control. `timeout` không đủ chứng minh firewall; PID/process name nhìn thấy qua socket không tự xác thực service intended là PostgreSQL; phải xác minh cấu hình ứng dụng/service riêng. Không gọi TCP/HTTP probe tới host không được phép kiểm tra. HTTP validation giảm một số input rủi ro nhưng không phải bộ bảo vệ SSRF toàn diện.

## Security and verification — `tools/security.py`, `verification.py`

| Tool | Tham số | Kết quả | Chế độ |
|---|---|---|---|
| `inspect_security_posture` | Không có | Đọc thông tin OS user/runtime và safety config, không xác nhận hệ thống hoàn toàn an toàn | Read-only |
| `verify_service_health` | `service_name` bắt buộc | Đọc active state; `healthy` chỉ khi query thành công và unit active | Read-only |
| `verify_endpoint` | `url` bắt buộc; optional `timeout_seconds` 0.1–5.0 | HTTP verification; HTTP 5xx có thể reachable nhưng không healthy | Read-only probe |

`RecoveryManager` là **class phục vụ hậu kiểm**, **không phải tool CLI độc lập**. Bounded retry chỉ lặp lại health checks, không tự restart nhiều lần. `PolicyEngine`, `ApprovalManager`, `ControlledExecutor` cũng là thành phần kiểm soát, **không phải read-only tools**.

## Optional external reference — `tools/tavily_search.py`

| Tool | Khi nào xuất hiện | Tham số | Giới hạn |
|---|---|---|---|
| `tavily_web_search` | `TAVILY_ENABLED=true` và `TAVILY_API_KEY` hợp lệ theo config | `query` bắt buộc 3–400 ký tự; `max_results` tùy chọn, tối đa theo cấu hình (1–5) | Search kết quả web không đáng tin cậy, không chứng minh trạng thái host, có network/API cost |

`llm_client.py` là adapter lập kế hoạch/tổng hợp qua OpenAI-compatible HTTP API, **không phải tool Registry**, và được tắt theo mặc định. Rule-based planner không yêu cầu LLM key hay Tavily key. Code và mock-based tests có tồn tại, nhưng **kết nối live LLM/Ollama và Tavily chưa được chấp nhận như bằng chứng live end-to-end trong post-merge QA**.

## Registration, policy, audit và hành động

- `register_builtin_tools(ToolRegistry(), config)` đăng ký **20 tools ở default**: 19 read-only và 1 `restart_service` state-changing; Tavily thêm đúng một tool khi bật có key. `--list-tools` hiển thị `STATE-CHANGING` và approval requirement của `restart_service` dù action đang disabled; hiển thị không đồng nghĩa được cấp quyền chạy.
- Investigation planner chỉ được gọi registered read-only tools. Default `agent.mode=observe`, `dry_run=true`, `max_steps=5`; Registry lọc schema và policy chặn nhánh mutation.
- `restart_service` yêu cầu `services.restart_enabled=true`, `agent.mode=assisted`, `dry_run=false`, policy `restart_service.allowed`, allowlist chính xác, approval phù hợp, audit gate và quyền OS tương ứng. Mặc định **không cho phép**; không có auto sudo hoặc arbitrary commands.
- `AuditLogger` khởi tạo SQLite ở `data/audit.db` khi chạy investigation; cần quyền ghi user-space. Console approval không phải xác thực mạnh; audit field redaction không đảm bảo xóa mọi dữ liệu nhạy cảm trong free text.
- Không suy diễn root cause chỉ từ process snapshot, TCP failure, listener, OOM line hoặc output LLM/Tavily. Bằng chứng ở `diagnostics.py` chia facts, hypotheses và next checks.

## Accepted baseline evidence and scope

Functional post-merge local verification tại `c05277e` (18/11/2026): **295 pytest PASS**, U-01 targeted **9 PASS**, U-02 độc lập **7 PASS**, R02/R03/INT-FIX-01 routing **59 PASS**, observe-mode unauthorized restart denial **2 PASS**, Ruff/compileall/diff check PASS. Các test nhóm con trùng với full suite và không được cộng dồn. U-02 test nguồn SHA-256 `a09b8864ce93c43d8e8252583affc25a4ca961d6021d829a186b39be20ddb804`; verbose log SHA-256 `ee8635e0ffc6544ee8237a8592783f947fe48a7f5c8dc90bc1b05f78b1d6c853` (không nằm trong repo). **Clean Ubuntu verification của FINAL-DOCS-01 và việc tích hợp tài liệu phải được QA/PM duyệt riêng**.

Tham khảo thêm: [README](../README.md), [architecture](architecture.md), [safety](safety-and-operations.md), [LLM/Tavily](llm-and-tavily-setup.md), [threat model](threat-model.md).
