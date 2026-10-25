# Cấu hình LLM và Tavily

## 1. API nào điền ở đâu?

- `TAVILY_API_KEY`: khóa **Tavily Search API**, chỉ dùng để tìm kiếm web.
- `LLM_API_KEY`: khóa của nhà cung cấp **mô hình chat/LLM** tương thích với endpoint `/chat/completions`.
- Hai khóa này là hai dịch vụ khác nhau. Tavily không thay thế LLM lập kế hoạch và tổng hợp bằng chứng.

Tạo file riêng từ mẫu:

```bash
cp .env.example .env
nano .env
```

Điền các biến tương ứng trong `.env` (không đưa khóa thật vào Git hoặc dán khóa vào đoạn chat):

```dotenv
TAVILY_API_KEY=tvly-PASTE_TAVILY_KEY_HERE
LLM_API_KEY=PASTE_MODEL_PROVIDER_KEY_HERE
LLM_MODEL=YOUR_MODEL_NAME
LLM_BASE_URL=https://api.openai.com/v1
LLM_ENABLED=true
TAVILY_ENABLED=true
```

Đây chỉ là mẫu định dạng. Thay `YOUR_MODEL_NAME`, endpoint và khóa bằng giá trị do nhà cung cấp LLM của bạn cung cấp. Nếu dùng endpoint OpenAI-compatible khác, thay `LLM_BASE_URL` bằng API root tương ứng (không thêm `/chat/completions` ở cuối).

Nếu chưa có LLM provider, giữ `LLM_ENABLED=false`; agent vẫn chạy theo luật. Bạn vẫn có thể cấu hình Tavily, nhưng Tavily đơn lẻ không biến workflow thành LLM-powered agent.

## 2. Xác nhận cấu hình

```bash
source .venv/bin/activate
linux-admin --check-config
linux-admin --list-tools
```

Khi cấu hình đúng, bạn sẽ thấy `LLM enabled: True`, `Tavily web search enabled: True` và tool `tavily_web_search` trong danh sách. `--check-config` không in giá trị API key.

## 3. Chạy điều tra end-to-end

Dùng tên service thật trong môi trường thử nghiệm của bạn:

```bash
linux-admin --investigate "Tại sao dịch vụ web demo-web.service không hoạt động?"
```

Agent gửi yêu cầu tới LLM để lập kế hoạch, chạy các tool read-only đã đăng ký, rồi gửi bằng chứng đã giới hạn và lọc secret trở lại LLM để tổng hợp báo cáo. LLM có thể chọn `tavily_web_search` khi cần tài liệu bên ngoài; nó không cần tìm web cho mọi sự cố.

Nếu LLM không truy cập được và `fallback_to_rules: true`, agent ghi rõ việc chuyển sang planner theo luật. Trường hợp tổng hợp bằng chứng thất bại cũng được báo rõ trong `findings`.

## 4. Quyền riêng tư và an toàn với API key

Khi LLM được bật, yêu cầu của người dùng và kết quả công cụ đã giới hạn/lọc secret
được gửi tới endpoint LLM đã cấu hình để lập kế hoạch hoặc tổng hợp bằng chứng. Bộ lọc
không thể bảo đảm loại bỏ mọi dữ liệu nhạy cảm trong mọi loại log; chỉ bật tính năng
này khi endpoint và dữ liệu gửi đi phù hợp với yêu cầu bảo mật của bạn.


- Không đặt API key trong `config/agent.yaml`, source code, test hoặc README.
- File `.env` phải được Git ignore. Chỉ commit `.env.example` với các giá trị trống.
- Nếu lỡ commit hoặc chia sẻ khóa thật, thu hồi/tạo khóa mới tại dashboard của nhà cung cấp.
- Nội dung log và kết quả tìm kiếm web là dữ liệu không đáng tin; không được dùng chúng làm chỉ thị để vượt policy.
- Giữ `mode: observe`, `dry_run: true` và service restart disabled cho đến khi test remediation trên service thử nghiệm.
