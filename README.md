# Linux AI System Administrator Agent

**Trạng thái:** prototype nghiên cứu/chạy thử trên Ubuntu; không phải công cụ quản trị Linux tự động hoàn toàn, chưa được đánh giá bảo mật để dùng trên production. Tài liệu này mô tả mã nguồn tại **functional baseline `c05277ecd26512337ea29619321e4c99531fc9c0`** (18/11/2026). Kiểm thử cài đặt Ubuntu sạch cho nhánh tài liệu `FINAL-DOCS-01` phải được thực hiện và nghiệm thu riêng; các lệnh bên dưới không tự chứng minh rằng bước đó đã hoàn tất.

Agent tiếp nhận mô tả sự cố, lập kế hoạch thu thập bằng chứng, gọi các công cụ chẩn đoán đã đăng ký, phân biệt **sự kiện đã quan sát / giả thuyết / bước kiểm tra tiếp theo**, ghi audit và trả kết quả điều tra. Luồng khắc phục có kiểm soát chỉ hỗ trợ **restart một systemd service được chỉ định và cho phép rõ ràng**; hành động này **bị khóa trong cấu hình mặc định**. Chỉ chạy các ví dụ read-only khi bắt đầu.

## 1. Khả năng đã triển khai

- Điều tra CPU, RAM, swap, uptime, dung lượng đĩa, tiến trình CPU/RAM và các điểm mount qua `psutil`.
- Lấy mẫu disk I/O theo thiết bị, tỷ lệ CPU iowait và read/write I/O theo tiến trình; xử lý counter reset, PID biến mất/tái sử dụng, thiếu quyền và dữ liệu không hỗ trợ.
- Xem trạng thái systemd, failed units, journal gần đây, kernel-log (gồm dấu hiệu OOM nếu hiện diện trong cửa sổ truy vấn), SSH/auth log và dấu hiệu đăng nhập thất bại theo ngưỡng.
- Quan sát network interfaces, TCP listening sockets/PID nhìn thấy được, kiểm tra TCP và HTTP(S) tới endpoint được cung cấp, với thời gian chờ giới hạn. HTTP checker không theo redirect.
- Chẩn đoán theo luật, lập kế hoạch có giới hạn `max_steps`, follow-up dựa trên bằng chứng, thông báo khi thiếu dữ liệu. Có tích hợp LLM OpenAI-compatible và Tavily **tùy chọn**, không cần chúng cho đường chạy rule-based.
- Policy deny-by-default, allowlist, approval gắn với action, audit SQLite và hậu kiểm sức khỏe cho workflow restart **chỉ khi được cấu hình/chấp thuận**.

**Không được suy diễn quá mức:** CPU/RAM là ảnh chụp ngắn tại thời điểm đo, không chứng minh áp lực kéo dài. Per-process I/O là mẫu hai lần đọc, **giới hạn 256 tiến trình/lần chụp và tối đa 10 bản ghi xuất ra**, được tính xấp xỉ trên khoảng `sample_seconds` (0,1–5 giây); quyền truy cập và thời điểm lấy mẫu ảnh hưởng độ bao phủ. Hoạt động đĩa của PID **không chứng minh** PID gây CPU iowait hay nghẽn thiết bị. Log OOM chỉ được phát hiện nếu có bản ghi phù hợp trong kernel journal, quyền truy cập và bộ lọc `priority`/`since_minutes`/`lines` cho phép đọc; không có log không đồng nghĩa không từng có OOM.

**Port 5432:** Công cụ hiện có cho phép quan sát listener, địa chỉ bind, PID hiển thị và kết quả TCP nếu endpoint thực sự được chỉ định. Agent **không tự động thực hiện trọn quy trình ping → TCP → firewall → bind**; không có tool ping hoặc điều khiển firewall. `TCP timeout` không chứng minh firewall chặn; socket trên 5432 không chứng minh PostgreSQL sở hữu nó. Cần bằng chứng ứng dụng/triển khai độc lập để kết luận owner. Xem [catalog](docs/tool-catalog.md).

## 2. Kiến trúc và ranh giới an toàn

```text
Yêu cầu người dùng → CLI (main.py) / load_config
                    → RuleBasedPlanner hoặc optional LLM/HybridPlanner
                    → ToolRegistry (schema + tool read-only đã đăng ký)
                    → psutil / systemctl đọc trạng thái / journalctl / TCP / HTTP
                    → ToolResult → diagnostics (facts / hypotheses / next checks)
                    → JSON / báo cáo CLI + audit SQLite

Đường hành động riêng (KHÔNG bật mặc định):
  ActionRequest → PolicyEngine → allowlist & explicit approval
                → ControlledExecutor + audit gate → restart_service
                → verify_service_health / verify_endpoint → audit kết quả
```

Module chính: `src/linux_admin/main.py` (CLI), `agent.py` (rule/LLM/hybrid planner, giới hạn bước và điều phối), `registry.py` và `contracts.py` (đăng ký/schema/result), `tools/` (công cụ), `diagnostics.py` (tổng hợp bằng chứng), `config.py` (YAML + env), `control.py` và `remediation_workflow.py` (policy/approval/hành động), `verification.py` (hậu kiểm), `audit.py` (SQLite), `llm_client.py` (LLM adapter). Xem [kiến trúc](docs/architecture.md), [an toàn](docs/safety-and-operations.md), [threat model](docs/threat-model.md).

## 3. Môi trường và phụ thuộc

- **Đích kiểm thử chính:** Ubuntu 22.04, Python 3.10.12 trên VM. `pyproject.toml` khai báo **Python `>=3.10`** nhưng không có chứng nhận tích hợp mọi phiên bản Python/Ubuntu. Các API `psutil` có phần đa nền tảng; các công cụ `systemctl`/`journalctl` yêu cầu Linux chạy systemd/journald. Trên VM, container, WSL hoặc user không đủ quyền, một số metric/log có thể không có.
- Cần có sẵn **Git, Python 3.10+, `venv` và `pip`** trong Ubuntu do người quản lý môi trường cung cấp. Không cần `sudo` để chạy các ví dụ bên dưới khi các thành phần này đã được cài. Clone và tải gói PyPI yêu cầu kết nối tới GitHub/PyPI trong lúc cài, nhưng **không cần API key LLM/Tavily**.
- Dependencies runtime khai báo: `psutil>=5.9,<8`, `PyYAML>=6,<7`, `python-dotenv>=1,<2`; extras `.[dev]`: `pytest>=8,<10`, `ruff>=0.6,<1`. Không có lockfile/pin từng bản; khi tái hiện, lưu phiên bản thực tế bằng `python -m pip freeze`.
- **Chế độ cài đặt được hướng dẫn và cần kiểm chứng:** editable install từ source checkout (`python -m pip install -e '.[dev]'`), giữ nguyên `config/` bên cạnh source. Theo `config.py`, mặc định cấu hình tìm tại project root suy từ đường dẫn mã nguồn. **Standalone wheel/install không kèm repo config chưa được xác thực**; với bố trí khác phải truyền `--config-dir` gồm ba YAML và kiểm tra audit path có quyền ghi.

## 4. Clone và cài đặt lần đầu (Ubuntu, user thường)

Dùng thông tin đăng nhập GitHub hợp lệ nếu repository yêu cầu. Ở thời điểm chuẩn bị tài liệu, nhánh `test` giữ functional baseline; để kiểm thử **release candidate tài liệu**, clone nhánh được công bố trong Draft PR `FINAL-DOCS-01` thay vì mặc định clone `main`.

```bash
# Sau khi reviewer cung cấp tên nhánh candidate, ví dụ:
DOC_BRANCH=docs/final-docs-01-20261118
REPO_URL=https://github.com/remjphong/linux_ai_system_administator_agent.git

# Dùng thư mục mới, không đè lên checkout đang có.
git clone --branch "$DOC_BRANCH" --single-branch "$REPO_URL" linux-admin-clean
cd linux-admin-clean

git rev-parse HEAD            # ghi lại exact documentation candidate SHA
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pip freeze          # lưu phiên bản deps cho báo cáo

# Không tạo .env và không cần key cho chạy theo luật.
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false linux-admin --check-config
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false linux-admin --list-tools
```

**Không dùng** `sudo pip install`, không copy `.env` hoặc `data/audit.db` từ VM developer. Môi trường mới cần quyền ghi trong checkout (audit SQLite mặc định `data/audit.db`). Tạo venv và cài các Python package là thao tác user-space, không phải nâng quyền quản trị hệ thống. Lệnh `--check-config` và `--list-tools` không cần API key và không tự tạo DB; `--investigate` sẽ khởi tạo SQLite audit nếu bật mặc định.

Nếu không thể dùng SSH, URL HTTPS ở trên dùng luồng xác thực do GitHub hỗ trợ; **không nhúng token vào URL, lệnh hoặc log**. Nếu không có `python3 -m venv`, hãy yêu cầu quản trị VM cung cấp package Python venv phù hợp, không sửa mã nguồn dự án để vượt lỗi môi trường.

## 5. First run an toàn (không cần LLM/Tavily)

Trong repo clone, sau `source .venv/bin/activate`:

```bash
# Đặt biến môi trường theo từng lệnh để không phụ thuộc .env ngoài repo.
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
linux-admin --investigate 'Inspect CPU and RAM usage. Read only.'

# Các nhóm specialized; chỉ đọc metrics và trạng thái local.
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
linux-admin --investigate 'Inspect all mount points. Read only.'

LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
linux-admin --investigate 'Inspect disk I/O and iowait. Read only.'

LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
linux-admin --investigate 'Inspect listening port 5432 on this host. Read only.'

# Có thể bị hạn chế bởi journal permissions; ghi lại status/limit trong báo cáo.
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
linux-admin --investigate 'Inspect kernel logs for OOM evidence. Read only.'
```

Các probe TCP/HTTP có thể **tạo kết nối mạng ra ngoài** khi bạn chỉ định URL/host; chỉ dùng đích mà bạn được phép kiểm tra. Tránh kiểm tra một service thật bằng `--restart-service`. Một cuộc điều tra có thể hoàn thành việc thu thập bằng chứng dù vẫn không xác định được root cause. CLI trả JSON chứa `status`, `steps`, `evidence`, `findings`, `remediation`; `remediation` không đồng nghĩa đã sửa được lỗi.

**Kiểm tra audit init** sau ít nhất một lần `--investigate`:

```bash
python - <<'PY'
from pathlib import Path
import sqlite3
p = Path('data/audit.db')
assert p.is_file(), 'audit SQLite was not initialized'
assert p.stat().st_size > 0
with sqlite3.connect(f'file:{p.resolve()}?mode=ro', uri=True) as db:
    table = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'").fetchone()
    count = db.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0]
assert table is not None and count > 0
print('AUDIT INIT PASS; events:', count)
PY
```

SQLite audit ghi vào thư mục user-space được ignore bởi Git; không phải chứng nhận chống sửa/xóa audit. Giữ quyền truy cập hợp lý và rà soát log trước khi chia sẻ.

## 6. CLI, cấu hình và key tùy chọn

| Lệnh | Vai trò |
|---|---|
| `linux-admin --help` / `--version` | Trợ giúp và phiên bản |
| `linux-admin --check-config` | Kiểm tra YAML/env và in thông số hiệu lực (không in key) |
| `linux-admin --list-tools` | Tool đang được đăng ký, phân biệt read-only/state-changing |
| `linux-admin --investigate 'REQUEST'` | Điều tra giới hạn bước; cũng có thể truyền natural-language request không kèm flag |
| `linux-admin --config-dir /absolute/path/to/config` | Nạp `agent.yaml`, `policy.yaml`, `services.yaml` từ thư mục riêng; kết hợp với một chế độ ở trên |
| `linux-admin --restart-service SERVICE --reason '...'` | Đường hành động có kiểm soát, **disabled theo default**, không dùng trong clean-install test |

Ba file cấu hình là `config/agent.yaml`, `config/policy.yaml`, `config/services.yaml`; `--config-dir` phù hợp nếu cần đổi vị trí cấu hình trên máy khác. Defaults: `agent.mode=observe`, `dry_run=true`, `max_steps=5`, `tool_timeout_seconds=10`, `audit.enabled=true` và đường dẫn `data/audit.db`, `policy.default_decision=deny`, `services.restart_enabled=false`. `config/services.yaml` chứa `demo-web.service` **chỉ như ví dụ**; không đảm bảo service tồn tại. `network.connectivity_check_url=https://example.com/` là probe cấu hình cho một số yêu cầu kiểm tra kết nối tổng quát, nên kiểm tra loại yêu cầu trước khi chạy nếu cần môi trường offline.

**LLM:** `llm_client.py` hiện thực adapter OpenAI-compatible (`/chat/completions`) cho planning/evidence synthesis. Mặc định disabled và planning dùng `rules`. Nếu muốn thử riêng trên môi trường được phép, tham khảo [LLM/Tavily setup](docs/llm-and-tavily-setup.md), sử dụng `LLM_ENABLED`, `LLM_PLANNING_MODE`, `LLM_MODEL`, `LLM_BASE_URL`, `LLM_API_KEY` của nhà cung cấp LLM. Với Ollama local, endpoint có thể là `http://127.0.0.1:11434/v1` và model đã thực sự cài trên host; đây là **tùy chọn cần vận hành dịch vụ riêng**, không phải bước bắt buộc hoặc kết quả live đã được QA độc lập xác nhận.

**Tavily:** `tavily_web_search` chỉ được đăng ký khi `TAVILY_ENABLED=true` **và** `TAVILY_API_KEY` có sẵn; là tìm kiếm web bên ngoài, không xác minh tình trạng local. LLM và Tavily là hai tích hợp độc lập. **Các tích hợp live LLM/Ollama và Tavily chưa được QA post-merge chấp nhận theo nghĩa chứng nhận hoạt động end-to-end với dịch vụ thật**; unit tests và adapter tồn tại không đủ để kết luận các API đang truy cập được. Không chia sẻ khóa hoặc dữ liệu nhạy cảm trong prompt/log.

## 7. Tool catalog và giới hạn chẩn đoán

Toàn bộ danh sách, input, output, điều kiện vận hành và trạng thái thay đổi hệ thống tại **[docs/tool-catalog.md](docs/tool-catalog.md)**. Hệ thống đăng ký **20 công cụ nội bộ ở cấu hình mặc định** (19 read-only, 1 `restart_service` state-changing bị vô hiệu hóa); `tavily_web_search` là công cụ thứ 21 khi được bật và có key. `--list-tools` là nguồn xác nhận trên máy cài thực tế. Các adapter phụ thuộc quyền đọc từ OS có thể trả về lỗi/không đủ dữ liệu; không thay kết quả thiếu bằng giả định.

## 8. Safety model

- Nhánh `--investigate` chỉ gọi registered **read-only tools**; đầu ra model, log, Tavily và lời nói của người dùng không tự cấp quyền hành động.
- Policy mặc định từ chối, restart disabled trong YAML, agent observe + dry_run; restart không được gọi qua Registry thông thường. `ControlledExecutor` yêu cầu exact allowlist/policy/approval, audit trước khi thực thi và hậu kiểm sau đó. Adapter dùng argv cố định, không có auto `sudo` hay arbitrary shell.
- `systemctl restart` thành công **không chứng minh** service/HTTP endpoint khỏe. Health verification và audit failure phải được phản ánh trong báo cáo. Không tự động lặp lại restart khi hậu kiểm thất bại.
- Console approval của local beta **không phải xác thực danh tính mạnh**. Bảo vệ audit DB, config, key; HTTP target validation không phải SSRF defense toàn diện. Không vận hành trên production hoặc thực thi thay đổi hệ thống thật bằng quy trình của tài liệu này.

## 9. Kiểm thử và bằng chứng chấp nhận

Từ **functional baseline `c05277e`** ngày 18/11/2026, developer post-merge verification ghi nhận:

| Nhóm | Bằng chứng đã báo cáo |
|---|---|
| Full suite | **295 pytest PASS** |
| U-01 process I/O targeted | 9 PASS |
| U-02 port 5432 independent scenarios | 7 PASS (bộ test độc lập ngoài repository) |
| R02/R03/INT-FIX-01 routing | 59 PASS |
| Observe-mode unauthorized restart denial | 2 PASS |
| Ruff, compileall, git diff | PASS |

Các tập targeted có thể nằm trong full suite; **không cộng** thành số test độc lập. Bằng chứng U-02 được bảo toàn theo SHA-256: nguồn test `a09b8864ce93c43d8e8252583affc25a4ca961d6021d829a186b39be20ddb804`; verbose log `ee8635e0ffc6544ee8237a8592783f947fe48a7f5c8dc90bc1b05f78b1d6c853`. Bộ test này không tự xuất hiện trong clone repo nếu không được cung cấp riêng. Kết quả trên máy clean phải ghi riêng; không sao chép kết luận cũ thành “đã chạy trên máy mới”.

Chạy regression từ **root repo** (venv đã bật):

```bash
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false python -m pytest -q
python -m ruff check .
python -m compileall -q src tests
git diff --check
# Optional targeted safety regressions:
LLM_ENABLED=false LLM_PLANNING_MODE=rules TAVILY_ENABLED=false \
python -m pytest -q tests/test_agent_workflow.py -k 'never_executes_state_changing_tool_directly or registry_denies_unapproved_restart or enforces_max_steps'
```

Tổng thể functional QA đã được chấp nhận ở baseline; **FINAL-DOCS-01 clean-install, doc-review và merge chưa được coi là hoàn tất** trước khi Tester/Reviewer/PM phê duyệt riêng.

## 10. Giới hạn đã biết và ngoài phạm vi

- Không được chứng nhận production-ready/security-certified; không có quản trị tự động toàn diện, không quản lý firewall, ping, cài/xóa package, xóa file hoặc thực thi shell tùy ý.
- Không được khẳng định xác định root cause chỉ qua CPU snapshot, iowait/tiến trình, TCP timeout hay một listener port. OOM/auth journaling phụ thuộc quyền đọc và filter; PID/socket owner có thể ẩn.
- Chưa có benchmark accuracy/coverage cho mô hình LLM trên Linux thật hoặc xác thực live Tavily trong post-merge QA. Tích hợp qua API có rủi ro lộ dữ liệu; chỉ chạy khi có chấp thuận.
- Môi trường package/version khác Ubuntu 22.04 + Python 3.10 cần được thử riêng. Standalone wheel không kèm YAML, config path không chuẩn, thư mục không ghi được audit, systemd/journal không tồn tại có thể làm một số bước lỗi.
- Test giả lập và fixture `demo-web.service` từ môi trường phát triển không được cài khi clone; không tự động cấu hình quyền hoặc service.

## 11. Cấu trúc dự án và phân công

```text
config/                 agent, policy, services YAML
src/linux_admin/        CLI, planner, registry, diagnostics, audit, controls
src/linux_admin/tools/  system / logs / network / services / security / Tavily
tests/                  unit, integration, safety và regression
 docs/                  architecture, catalog, safety, threat-model, LLM setup
pyproject.toml          dependencies, entrypoint, pytest, Ruff
.env.example            mẫu cấu hình key tùy chọn; không chứa key thật
```

Theo phân vai/module ownership ghi trong [docs/architecture.md](docs/architecture.md): **Nhóm A** phụ trách core contracts/config/agent/LLM/registry/audit/CLI/packaging/README; **Nhóm B** phụ trách system/log/network/security tools, tool tests và catalog; **Nhóm C** phụ trách control/service actions/verification/policy/safety docs. Đây là phân công module theo tài liệu repository, **không suy đoán tên cá nhân hoặc tư cách nghiệm thu**.

**Thay đổi tài liệu:** `FINAL-DOCS-01` chỉ được sửa `README.md` và `docs/tool-catalog.md`. Nếu clean-install phát hiện lỗi chức năng/packaging, ghi reproduction và báo PM; không tự đổi code hoặc test để làm pass.
