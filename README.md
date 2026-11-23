# Linux AI System Administrator Agent

Linux Admin Agent thu thập số liệu trên máy Linux và hỗ trợ điều tra sự cố bằng câu hỏi tiếng Việt hoặc tiếng Anh. Dashboard cập nhật CPU, RAM, swap, dung lượng đĩa `/` và 10 tiến trình dùng nhiều RAM. Khi điều tra qua CLI hoặc chat terminal, Agent chọn công cụ, ghi nhận bằng chứng và đề xuất bước kiểm tra tiếp theo.

**Trạng thái:** Bản mẫu nghiên cứu, dùng để demo và kiểm thử trên máy Linux. Cấu hình mặc định chỉ quan sát.

## 1. Lấy mã nguồn

**Yêu cầu:** Ubuntu/Linux, Python 3.10 trở lên, Git, `venv` và `pip`. Nếu dùng VS Code Remote SSH, chạy các lệnh trong terminal trên máy Ubuntu. Dùng tài khoản thường để cài và chạy dự án.

### Clone lần đầu

```bash
git clone --branch main https://github.com/remjphong/linux_ai_system_administator_agent.git
cd linux_ai_system_administator_agent
```

### Cập nhật bản clone hiện có

Mở terminal trong thư mục repo và kiểm tra `git status`. Nếu đang có thay đổi chưa commit, lưu công việc trên nhánh đang làm trước khi chuyển sang `main`.

```bash
git status --short --branch
git switch main && git pull --ff-only origin main
git log -1 --oneline
```

Nếu `git pull --ff-only` báo hai nhánh đã phân kỳ, gửi kết quả `git status --short --branch` và thông báo lỗi cho nhóm để đối chiếu.

## 2. Cài môi trường Python

Chạy trong thư mục repo sau khi clone hoặc cập nhật. Giữ terminal này cho các lệnh tiếp theo.

```bash
(test -x .venv/bin/python || python3 -m venv .venv) &&
source .venv/bin/activate &&
python -m pip install -e '.[dev]'
```

Nếu Ubuntu báo thiếu `venv`, cài gói hệ thống bằng `sudo apt install python3-venv` nếu bạn có quyền quản trị, rồi chạy lại các lệnh trên. Bản kiểm thử mặc định chạy bằng rules và không cần API key.

## 3. Kiểm thử tự động

```bash
python -m pytest -q &&
python -m ruff check . &&
python -m compileall -q src tests
```

Kết quả đạt khi pytest không báo test fail, Ruff báo `All checks passed!` và `compileall` kết thúc không lỗi. Nếu test đọc network interfaces gặp `PermissionError` trong sandbox, chạy lại trên máy Ubuntu của nhóm và ghi rõ môi trường cùng tên test bị lỗi.

## 4. Chạy thử dashboard web

```bash
python -m linux_admin.dashboard --port 8765
```

Giữ terminal chạy và mở trình duyệt theo môi trường:

| Môi trường | Địa chỉ |
| --- | --- |
| Trình duyệt chạy trên chính máy Ubuntu | Mở `http://127.0.0.1:8765`. |
| VS Code kết nối Ubuntu qua Remote SSH | Mở tab **Ports**, chọn **Forward a Port**, nhập `8765` và mở **Forwarded Address**. Nếu cổng phía máy bạn bị đổi, dùng địa chỉ do VS Code hiển thị. |

Dashboard đạt smoke test khi bốn ô CPU, RAM, swap và đĩa hiển thị số liệu, bảng tiến trình có dữ liệu, và dòng **Mẫu lúc** đổi sau vài giây mà bạn không cần tải lại trang. CPU hoặc swap bằng `0%` vẫn là giá trị hợp lệ.

Nếu muốn đối chiếu dữ liệu thô, mở `/api/snapshot` trên cùng địa chỉ. JSON gồm `timestamp`, `system`, `disk` và `processes`. Dừng dashboard bằng **Ctrl+C**. Server chỉ lắng nghe trên `127.0.0.1` của máy chạy Python.

### Bật chat web với LLM và Tavily

Trong `.env`, đặt `LLM_ENABLED=true`, `LLM_PLANNING_MODE=llm` và
`TAVILY_ENABLED=true`. Giữ `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL` và các key
phù hợp với dịch vụ của bạn. Xem [cấu hình LLM và Tavily](docs/llm-and-tavily-setup.md).

```bash
python -m linux_admin.dashboard --port 8765 --chat --config-dir config
```

Chat web bật tổng hợp bằng LLM và chạy điều tra chỉ đọc. Mỗi lượt xử lý một câu
hỏi độc lập. Tavily được dùng khi câu hỏi yêu cầu tra cứu. Ví dụ:

- `Kiểm tra CPU và RAM hiện tại rồi tóm tắt kết quả.`
- `Tra cứu trên web bằng Tavily tài liệu chính thức về Linux CPU iowait.`

Giao diện hiển thị thời gian từ lúc gửi tới lúc nhận kết quả, thời gian backend,
trạng thái từng tool và nguồn tham khảo. Để xác nhận cả hai tích hợp, kiểm tra
model xuất hiện bên dưới bản tổng hợp và `tavily_web_search` có trạng thái
`success` trong lượt tra cứu. Nếu dùng LLM cloud, câu hỏi và bằng chứng đã thu
thập có thể được gửi tới nhà cung cấp. Giữ API key trong `.env`.

## 5. Chạy thử CLI và chat terminal

Dùng terminal thứ hai nếu muốn giữ dashboard chạy. Kích hoạt lại `.venv` nếu vừa mở terminal mới.

```bash
source .venv/bin/activate
(
  export LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false
  linux-admin --config-dir "$PWD/config" --check-config &&
  linux-admin --config-dir "$PWD/config" --list-tools &&
  linux-admin --config-dir "$PWD/config" --json \
    --investigate "Kiểm tra CPU và RAM. Chỉ kiểm tra."
)
```

Với cấu hình mặc định, kiểm tra `Agent mode: observe`, `Dry-run: True` và `Service restart enabled: False`. Trong JSON, tìm `status: completed`, hai tool `get_system_overview` và `list_top_processes` có trạng thái `success`, cùng `remediation.status: not_proposed`. Lượt điều tra có thể tạo hoặc cập nhật SQLite tại `data/audit.db`.

Để thử chat bằng cùng cấu hình rules:

```bash
LINUX_ADMIN_CONFIG_DIR="$PWD/config" LLM_ENABLED=false \
LLM_PLANNING_MODE=rules TAVILY_ENABLED=false bash ./linux-admin-chat
```

Nhập lần lượt `Kiểm tra CPU và RAM. Chỉ kiểm tra.`, `tools`, `history` và `exit`. Lượt hỏi đầu tiên phải trả về báo cáo, còn `tools` và `history` phải hiển thị thông tin về lượt điều tra vừa chạy.

Khi báo kết quả cho nhóm, gửi **commit SHA, phiên bản Ubuntu/Python, kết quả pytest/Ruff và kết quả thử dashboard**. Nếu có lỗi, kèm lệnh và thông báo lỗi. Giữ riêng `.env` và API key.

## Cấu hình và giới hạn

- `config/agent.yaml` chứa chế độ chạy, giới hạn bước điều tra, thiết lập audit và các tích hợp tùy chọn. `config/policy.yaml` và `config/services.yaml` chứa policy và danh sách service.
- Mặc định, Agent dùng rules, tối đa 5 bước điều tra, bật SQLite audit và tắt restart, LLM, Tavily. Các tích hợp live và quy trình restart có kiểm soát cần được kiểm thử riêng.
- Khả năng đọc systemd, journald, tiến trình và thông tin mạng phụ thuộc vào môi trường và quyền của tài khoản chạy Agent. Các số liệu dashboard là mẫu quan sát tại thời điểm đo.

## Tài liệu

| Tài liệu | Nội dung |
| --- | --- |
| [Kiến trúc](docs/architecture.md) | Thành phần và luồng dữ liệu |
| [Danh mục công cụ](docs/tool-catalog.md) | Chức năng, tham số và giới hạn |
| [An toàn và vận hành](docs/safety-and-operations.md) | Policy, phê duyệt và audit |
| [Mô hình mối đe dọa](docs/threat-model.md) | Ranh giới tin cậy và rủi ro |
| [Cấu hình LLM và Tavily](docs/llm-and-tavily-setup.md) | Tích hợp mô hình và tìm kiếm web |
