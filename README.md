# Linux AI System Administrator Agent

Agent hỗ trợ điều tra sự cố Linux và đề xuất khắc phục có kiểm soát. Hệ thống thu thập bằng chứng bằng các công cụ đã đăng ký, kiểm tra policy, yêu cầu người vận hành phê duyệt hành động thay đổi hệ thống, rồi xác minh lại sau khi thực thi.

## 1. Trạng thái hiện tại

**V1 prototype — đã chứng minh một workflow khắc phục đầu-cuối trên Ubuntu VM.** Trong lần nghiệm thu thực tế, agent phát hiện một service thử nghiệm ở trạng thái `failed`, đề xuất restart, chờ phê duyệt, restart service, xác minh service `active` và endpoint HTTP trả về `200`, rồi báo `resolved=true`. Audit SQLite có đủ sự kiện policy, phê duyệt, thực thi và xác minh.

Trạng thái kiểm thử gần nhất (27/10/2026): **189 test passed**; Ruff, `compileall` và `git diff --check` đều thành công.

Giới hạn hiện tại:
- Các hành động khắc phục còn hạn chế; restart chỉ được đề xuất khi request nêu rõ đúng một service và bằng chứng cho thấy service đang `failed`.
- Agent không tự đoán service sở hữu một endpoint nếu chưa có bằng chứng; khi thiếu thông tin cần hỏi làm rõ.
- Các nhánh từ chối, policy chặn và lỗi xác minh có unit test; cần tiếp tục tăng kiểm thử tích hợp đầu-cuối cho các tình huống thất bại.
- Dịch vụ `linux-admin-v1-demo.service` dùng trong nghiệm thu là fixture được tạo thủ công trên VM phát triển, **không được cài tự động khi clone repo**.

## 2. Môi trường yêu cầu

- Ubuntu/Linux có `systemd` để dùng các công cụ quản trị dịch vụ.
- Git và Python. Dự án đã được chạy trên Ubuntu 22.04 với Python 3.10.12.
- Quyền `sudo` chỉ cần cho các thao tác quản trị hoặc khi tự dựng service thử nghiệm; chạy unit test không cần quyền quản trị.

## 3. Clone và cài đặt

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/remjphong/linux_ai_system_administator_agent.git
cd linux_ai_system_administator_agent

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Mỗi lần mở terminal mới, kích hoạt môi trường trước khi chạy lệnh:

```bash
cd ~/project/linux_ai_system_administator_agent
source .venv/bin/activate
```

Nếu clone vào thư mục khác, thay đường dẫn `cd` tương ứng.

## 4. Cấu hình

Các file YAML chính nằm trong `config/`:

| File | Vai trò |
|---|---|
| `config/agent.yaml` | Chế độ agent, giới hạn bước, timeout, LLM, Tavily và audit. |
| `config/policy.yaml` | Policy hành động; mặc định từ chối nếu không có quyền cho phép rõ ràng. |
| `config/services.yaml` | Allowlist service và cờ bật/tắt restart. |

**Mặc định an toàn:** `agent.mode=observe`, `dry_run=true`, `restart_service` bị policy từ chối, `services.restart_enabled=false`, audit bật. Service mẫu `demo-web.service` trong allowlist chỉ là ví dụ cấu hình và có thể không tồn tại trên máy.

### LLM và tìm kiếm web (tùy chọn)

Agent có thể chạy ở chế độ rule-based mà không cần LLM hay Tavily. Môi trường phát triển của tác giả dùng Ollama với `qwen2.5:1.5b` qua API tương thích OpenAI tại `http://127.0.0.1:11434/v1`; Tavily được bật riêng khi có API key.

Nếu muốn dùng cấu hình tương tự, cài đặt và khởi động Ollama, tải model:

```bash
ollama pull qwen2.5:1.5b
```

Tạo file `.env` ở thư mục gốc dự án nếu cần override cấu hình. Ví dụ dưới đây dùng Ollama cục bộ; không cần bật Tavily nếu chưa có API key:

```dotenv
LLM_ENABLED=true
LLM_PROVIDER=openai_compatible
LLM_MODEL=qwen2.5:1.5b
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_API_KEY=ollama
LLM_PLANNING_MODE=llm
TAVILY_ENABLED=false
```

Để tra cứu web, bật `TAVILY_ENABLED=true` và đặt `TAVILY_API_KEY` bằng key riêng của bạn. **Không commit `.env`, API key hoặc thông tin bí mật lên Git.** Tùy chọn cấu hình từ môi trường có thể ghi đè giá trị YAML; dùng `linux-admin --check-config` để xem cấu hình hiệu lực.

## 5. Các lệnh sử dụng

### Kiểm tra cấu hình và danh sách công cụ

```bash
linux-admin --check-config
linux-admin --list-tools
```

### Chạy điều tra chỉ đọc

Ví dụ kiểm tra tài nguyên và lỗi hệ thống mà không thay đổi máy:

```bash
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
linux-admin --investigate \
  "Inspect CPU and memory usage and recent system errors. Use read-only tools and do not change system state."
```

Kiểm tra một endpoint được chỉ định rõ ràng:

```bash
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
linux-admin --investigate \
  "Check whether http://127.0.0.1:11434/ is reachable. Use read-only tools and do not change system state."
```

Ví dụ endpoint thứ hai phù hợp khi Ollama đang chạy; thay URL bằng endpoint thực tế cần kiểm tra. Kết quả là JSON gồm findings, evidence, đề xuất hoặc lý do không đề xuất, cùng trạng thái resolution.

### Dùng thư mục cấu hình riêng

CLI hỗ trợ nạp `agent.yaml`, `policy.yaml` và `services.yaml` từ một thư mục riêng:

```bash
linux-admin --check-config --config-dir /path/to/config-dir
```

Chỉ dùng cấu hình có `assisted`, `dry_run=false` và quyền restart được bật khi đã kiểm tra kỹ policy, allowlist, audit, cơ chế phê duyệt và phạm vi tác động. Không dùng cấu hình thử nghiệm để quản trị máy production.

## 6. Chạy kiểm thử

Chạy toàn bộ test suite:

```bash
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
timeout 30s python -m pytest -q
```

Chạy các kiểm tra chất lượng:

```bash
python -m ruff check src tests
python -m compileall -q src tests
git diff --check
```

Chạy riêng các test liên quan workflow khắc phục:

```bash
python -m pytest -q tests/test_remediation_workflow.py tests/test_agent_workflow.py
```

Unit test dùng công cụ giả ở những nơi thích hợp; chúng không thay thế kiểm thử tích hợp trên một máy thử nghiệm an toàn.

## 7. Workflow khắc phục và an toàn

Workflow mục tiêu:

1. Nhận yêu cầu và thu thập bằng chứng chỉ đọc.
2. Chẩn đoán, phân biệt sự thật đã quan sát với giả thuyết.
3. Tạo đề xuất có mục tiêu, lý do, bằng chứng, rủi ro và kế hoạch xác minh.
4. Kiểm tra policy và yêu cầu người vận hành phê duyệt.
5. Thực thi hành động đã được cho phép và ghi audit.
6. Kiểm tra lại trạng thái service và, khi phù hợp, endpoint ban đầu.
7. Báo cáo `resolved`, `unresolved` hoặc chưa thể xác minh dựa trên kết quả hậu kiểm.

`systemctl restart` trả về thành công **không tự nó chứng minh** sự cố đã được khắc phục. Với endpoint HTTP, agent cần xác minh endpoint sau hành động. Khi audit hoặc hậu kiểm thất bại, không được tuyên bố đã phục hồi thành công.

Không chạy `--restart-service` hoặc bật quyền restart cho một service thật nếu chưa xác nhận service đó nằm trong allowlist, policy cho phép, audit bật và cơ chế phê duyệt đang hoạt động. Cấu hình mặc định cố ý giữ restart bị vô hiệu hóa.

## 8. Cấu trúc mã nguồn

- `src/linux_admin/agent.py`: planner, điều phối điều tra và thực thi công cụ chỉ đọc.
- `src/linux_admin/tools/`: công cụ hệ thống, service, log, network, security và Tavily.
- `src/linux_admin/diagnostics.py`: chẩn đoán dựa trên bằng chứng.
- `src/linux_admin/remediation_workflow.py`: đề xuất, phê duyệt, thực thi, hậu kiểm và báo cáo khắc phục.
- `src/linux_admin/control.py`: kiểm tra policy, quản lý phê duyệt và thực thi có kiểm soát.
- `src/linux_admin/verification.py`: kiểm tra sức khỏe sau hành động.
- `src/linux_admin/audit.py`: audit log lưu bằng SQLite.
- `tests/`: unit test và test workflow.

## 9. Ghi chú phát triển

- Giữ cấu hình mặc định ở chế độ an toàn; dùng cấu hình riêng và dịch vụ dùng một lần cho nghiệm thu hành động thật.
- Không suy đoán service owner từ URL hoặc từ log không liên quan.
- Mỗi kết luận `resolved=true` phải dựa trên các kiểm tra hậu kiểm đã qua, không chỉ dựa vào việc lệnh thay đổi hệ thống trả về thành công.
