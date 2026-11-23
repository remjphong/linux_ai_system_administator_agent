# Linux AI System Administrator Agent

Giám sát máy Linux, điều tra sự cố và xác minh khắc phục. Dashboard cập nhật CPU, RAM, swap, đĩa và tiến trình. Hai bài kiểm thử chính dưới đây chạy trên Ubuntu với Python 3.10+ và không cần API key.

## 1. Cài đặt

**Clone lần đầu**

```bash
git clone --branch main https://github.com/remjphong/linux_ai_system_administator_agent.git
cd linux_ai_system_administator_agent
```

**Đã clone** — chạy trong thư mục repo sau khi lưu thay đổi local.

```bash
git switch main && git pull --ff-only origin main
```

**Cài môi trường** — dùng chung cho cả hai trường hợp.

```bash
(test -x .venv/bin/python || python3 -m venv .venv) &&
.venv/bin/python -m pip install -e '.[dev]'
```

Nếu Ubuntu báo thiếu `venv`, cài `python3-venv` rồi chạy lại.

## 2. Thành viên 1 · Kiểm thử mã và CLI

```bash
GROQ_API_KEY= GROQ_MODEL= LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
  .venv/bin/python -m pytest -q &&
.venv/bin/python -m ruff check . &&
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
  .venv/bin/linux-admin --config-dir config --json --investigate "Kiểm tra CPU và RAM. Chỉ kiểm tra."
```

**Đạt khi** pytest không có test fail, Ruff báo `All checks passed!`, và CLI trả `status: completed` với kết quả đọc CPU/RAM. Nếu có lỗi quyền đọc mạng hoặc nhật ký, ghi lại tên test hoặc tool cùng thông báo lỗi.

## 3. Thành viên 2 · Kiểm thử dashboard và phục hồi

```bash
.venv/bin/python -m linux_admin.dashboard --port 8765 --monitor
```

Mở **http://127.0.0.1:8765**. Nếu dùng VS Code Remote SSH, vào **Ports → Forward a Port → 8765** và mở **Forwarded Address**. Nếu cổng đã bận, đổi `--port` và mở đúng cổng tương ứng. Dừng dashboard bằng `Ctrl+C`.

| Bước | Kết quả mong đợi |
| --- | --- |
| Mở dashboard và đợi hai mẫu | CPU, RAM, swap, đĩa và bảng tiến trình có dữ liệu. Dòng **Mẫu lúc** tự cập nhật. |
| Trong **Mô phỏng sự cố**, chọn **Dịch vụ trả HTTP 503** rồi bấm **Tạo sự cố** | **Sự cố giám sát** xuất hiện một dòng đang mở, có bằng chứng HTTP `503`. |
| Mở **Công cụ và các bước**, rồi bấm **Xác nhận khắc phục** | Hậu kiểm nhận HTTP `200`. Dashboard báo dịch vụ ổn định và dòng sự cố đổi thành **Tín hiệu đã hết**. |
| Lặp lại với **Dịch vụ ngừng lắng nghe** | Dashboard phát hiện lỗi kết nối. Sau khắc phục, hậu kiểm nhận lại HTTP `200`. |

Các bài thử trên web dùng dịch vụ HTTP loopback riêng. Restart unit systemd đi qua CLI, policy và phê duyệt. [An toàn và vận hành](docs/safety-and-operations.md)

## Tùy chọn · Kiểm thử chat web

Tạo `.env` từ `.env.example` nếu chưa có. Đặt `LLM_ENABLED=true`, `LLM_PLANNING_MODE=llm` và `TAVILY_ENABLED=true`, rồi điền cấu hình LLM và key Tavily. Khi dùng Groq, cài thêm `.[groq]` và đặt `GROQ_MODEL`, `GROQ_API_KEY`. Giữ các biến `LLM_*` trỏ tới Ollama nếu muốn dùng Ollama dự phòng. Giữ key trong `.env`. [Cấu hình LLM và Tavily](docs/llm-and-tavily-setup.md)

```bash
.venv/bin/python -m pip install -e '.[groq]'
.venv/bin/python -m linux_admin.dashboard --port 8765 --monitor --chat --config-dir config
```

Dừng dashboard cũ trước khi chạy lại trên cùng cổng. Thử câu **“So sánh tải CPU, RAM và tình trạng dịch vụ trên máy này.”** Mở **Chi tiết kiểm tra** để đối chiếu công cụ, kết quả và thời gian. Thử thêm một câu yêu cầu tra cứu Tavily nếu cần xác nhận tìm kiếm web.

## Báo kết quả cho nhóm

Gửi commit đang thử (`git rev-parse --short HEAD`), phiên bản Ubuntu/Python, các bước đạt hoặc lỗi, và ảnh trước/sau khi khắc phục nếu thử dashboard. Khi có lỗi, kèm lệnh đã chạy và thông báo lỗi.

[Tài liệu kiến trúc](docs/architecture.md) · [Danh mục công cụ](docs/tool-catalog.md) · [Mô hình mối đe dọa](docs/threat-model.md)
