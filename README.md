# VTeen Admin Suite Plugin (`vteen-admin-suite`)

Plugin C-ABI độc lập dành cho **CLIProxyAPI**, cung cấp bộ quản trị toàn diện **"BẢNG GIÁ & QUẢN TRỊ"** bao gồm 11 module quản lý.

## Tính năng (11 Modules)
1. **Bảng Giá Model (VNĐ)** (`/pricing`): Cấu hình đơn giá token input / output cho từng model bằng VNĐ.
2. **Quản Lý & Tạo API Keys** (`/keys`): Cấp phát, phân quyền, giới hạn hạn mức và quản lý khóa API khách hàng.
3. **Token Từng Tài Khoản (Auths)** (`/auths`): Thống kê chi tiết số lượng token tiêu thụ theo từng tài khoản upstream (Claude, Gemini, Codex, OpenAI).
4. **Đăng Nhập Kiro (AWS)** (`/kiro_oauth`): Khởi tạo phiên xác thực AWS Builder ID / SSO để bổ sung token vào pool.
5. **Nhật Ký & Check Lỗi** (`/logs`): Giám sát request logs real-time qua SSE, lọc lỗi và phân tích độ trễ.
6. **Bot Telegram & SePay** (`/telebot`): Cấu hình bot token, admin chat ID và cổng thanh toán tự động SePay.
7. **Auto Event Telegram** (`/autoevent`): Subsystem userbot tự động tham gia sự kiện và click button nhận quota vòng quay theo luồng sub-30ms.
8. **AI Chat Bot** (`/aibot`): Cấu hình trợ lý ảo CSKH AI thông minh (model, prompt, nhiệt độ).
9. **IP Bị Cấm (Banned IPs)** (`/banned_ips`): Danh sách các IP bị chặn và công cụ gỡ cấm IP.
10. **Đổi Mật Khẩu Admin** (`/password`): Thay đổi mật khẩu quản trị viên an toàn.
11. **Kiểm Tra Model (Test)** (`/test`): Gửi request trực tiếp để kiểm tra kết nối và độ trễ của model.

## Kiến trúc & Bảo mật
- Chuẩn native C-ABI theo SDK của CLIProxyAPI (`sdk/pluginabi`, `sdk/pluginapi`).
- Tự động đăng ký qua `management.register` với route chính `/app` và 11 sub-resources.
- Bảo mật nghiêm ngặt: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, CSP `same-origin`.
- Không rò rỉ token hoặc secret trong URL hoặc HTML.

## Hướng dẫn Biên dịch (Build)
```bash
# Windows (.dll)
cd go
go build -buildmode=c-shared -o ../vteen-admin-suite.dll .

# Linux (.so)
cd go
go build -buildmode=c-shared -o ../vteen-admin-suite.so .
```

## Cài đặt vào CLIProxyAPI
1. Đặt file thư viện đã biên dịch (`vteen-admin-suite.dll` hoặc `vteen-admin-suite.so`) vào thư mục `plugins/` của máy chủ CLIProxyAPI.
2. Cấu hình trong `config.yaml`:
```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    vteen-admin-suite:
      enabled: true
      priority: 1
```
3. Khởi động lại CLIProxyAPI và mở trang quản trị `/management.html`. Nhóm menu **"BẢNG GIÁ & QUẢN TRỊ"** sẽ tự động xuất hiện trên thanh điều hướng.

