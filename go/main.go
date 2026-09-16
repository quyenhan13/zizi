package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	pluginName          = "vteen-admin-suite"
	pluginDisplayName   = "Bảng Giá & Quản Trị (VTeen Suite)"
	pluginVer           = "1.0.0"
	resourceApp         = "/app"
	healthRoute         = "/vteen-admin-suite/health"
	resourceAppFullPath = "/v0/resource/plugins/vteen-admin-suite/app"
	healthRouteFullPath = "/v0/management/vteen-admin-suite/health"
	shellNonceTag       = "__VTEEN_NONCE__"
)

// resourceHeaders builds the strict same-origin framing policy for the plugin
// resource shell. It uses a per-response nonce so the static inline <style> and
// <script> blocks are allowed without 'unsafe-inline'; no foreign origins are
// permitted. The parent management panel's own DENY/frame-ancestors policy is
// unaffected — this only governs the iframe document itself.
func resourceHeaders(nonce string) http.Header {
	csp := "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; " +
		"form-action 'self'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; " +
		"script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'nonce-" + nonce + "'"
	return http.Header{
		"Content-Type":           []string{"text/html; charset=utf-8"},
		"Cache-Control":          []string{"no-store"},
		"Referrer-Policy":        []string{"no-referrer"},
		"X-Content-Type-Options": []string{"nosniff"},
		"X-Frame-Options":        []string{"SAMEORIGIN"},
		"Content-Security-Policy": []string{csp},
	}
}

func newNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "vteen-static-nonce"
	}
	return fmt.Sprintf("%x", buf)
}

const appShellHTML = `<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bảng Giá & Quản Trị - CLIProxyAPI</title>
<style nonce="__VTEEN_NONCE__">
  :root {
    --bg-main: #0b0f17;
    --bg-card: #111622;
    --bg-sidebar: #0e131e;
    --bg-input: #171e2e;
    --border-color: rgba(255, 255, 255, 0.08);
    --border-hover: rgba(255, 255, 255, 0.16);
    --primary: #6366f1;
    --primary-hover: #4f46e5;
    --primary-light: rgba(99, 102, 241, 0.15);
    --success: #10b981;
    --success-light: rgba(16, 185, 129, 0.15);
    --warning: #f59e0b;
    --danger: #ef4444;
    --danger-light: rgba(239, 68, 68, 0.15);
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg-main);
    color: var(--text-primary);
    display: flex;
    height: 100vh;
    overflow: hidden;
  }
  #suiteSidebar {
    width: 250px;
    background: var(--bg-sidebar);
    border-right: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }
  .sidebar-header {
    padding: 16px 18px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .sidebar-header h2 {
    font-size: 13px;
    font-weight: 700;
    margin: 0;
    letter-spacing: 0.05em;
    color: #cbd5e1;
    text-transform: uppercase;
  }
  .nav-list {
    list-style: none;
    padding: 10px 8px;
    margin: 0;
    overflow-y: auto;
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .nav-btn {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 12px;
    background: transparent;
    border: none;
    color: #94a3b8;
    border-radius: 7px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    text-align: left;
    transition: all 0.15s ease;
  }
  .nav-btn:hover {
    background: rgba(255, 255, 255, 0.04);
    color: #f1f5f9;
  }
  .nav-btn.active {
    background: rgba(99, 102, 241, 0.15);
    color: #818cf8;
    font-weight: 600;
  }
  .nav-btn svg { flex-shrink: 0; }
  #mainContent {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .content-header {
    padding: 14px 24px;
    border-bottom: 1px solid var(--border-color);
    background: rgba(17, 22, 34, 0.6);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .content-header h1 {
    font-size: 16px;
    font-weight: 600;
    margin: 0;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .content-body {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }
  .tab-pane { display: none; }
  .tab-pane.active { display: block; }
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 20px;
  }
  .card h3 {
    margin: 0 0 12px 0;
    font-size: 14px;
    font-weight: 600;
    color: #f1f5f9;
  }
  .btn {
    padding: 8px 16px;
    border-radius: 7px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    border: none;
    transition: all 0.15s;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .btn-primary { background: var(--primary); color: #fff; }
  .btn-primary:hover { background: var(--primary-hover); }
  .btn-danger { background: var(--danger-light); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
  .btn-danger:hover { background: rgba(239, 68, 68, 0.25); }
  .btn-secondary { background: rgba(255, 255, 255, 0.06); color: #cbd5e1; border: 1px solid var(--border-color); }
  .btn-secondary:hover { background: rgba(255, 255, 255, 0.1); }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th, td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border-color);
    text-align: left;
  }
  th { color: var(--text-muted); font-weight: 600; font-size: 12px; }
  tr:hover td { background: rgba(255, 255, 255, 0.02); }
  .badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge-success { background: var(--success-light); color: #34d399; }
  .badge-danger { background: var(--danger-light); color: #f87171; }
  input, select, textarea {
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    color: #f1f5f9;
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 13px;
    outline: none;
    width: 100%;
  }
  input:focus, select:focus, textarea:focus {
    border-color: var(--primary);
  }
  .form-group {
    margin-bottom: 14px;
  }
  .form-group label {
    display: block;
    margin-bottom: 6px;
    font-size: 12px;
    color: var(--text-secondary);
  }
</style>
</head>
<body>
  <div id="suiteSidebar">
    <div class="sidebar-header">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg>
      <h2>BẢNG GIÁ & QUẢN TRỊ</h2>
    </div>
    <ul class="nav-list">
      <li><button class="nav-btn active" data-tab="pricing"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg> Bảng Giá Model (VNĐ)</button></li>
      <li><button class="nav-btn" data-tab="keys"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-1-1l-3 3m-1-1l-3 3M3 21l9-9m3-3a5 5 0 10-7-7 5 5 0 007 7z"/></svg> Quản Lý & Tạo API Keys</button></li>
      <li><button class="nav-btn" data-tab="auths"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg> Token Từng Tài Khoản (Auths)</button></li>
      <li><button class="nav-btn" data-tab="kiro_oauth"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg> Đăng Nhập Kiro (AWS)</button></li>
      <li><button class="nav-btn" data-tab="logs"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg> Nhật Ký & Check Lỗi</button></li>
      <li><button class="nav-btn" data-tab="telebot"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg> Bot Telegram & SePay</button></li>
      <li><button class="nav-btn" data-tab="autoevent"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg> Auto Event Telegram</button></li>
      <li><button class="nav-btn" data-tab="aibot"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg> AI Chat Bot</button></li>
      <li><button class="nav-btn" data-tab="banned_ips"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> IP Bị Cấm (Banned IPs)</button></li>
      <li><button class="nav-btn" data-tab="password"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Đổi Mật Khẩu Admin</button></li>
      <li><button class="nav-btn" data-tab="test"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 2v7.31M14 9.3V1.99M8.5 2h7M14 9.3a6.5 6.5 0 1 1-4 0"/></svg> Kiểm Tra Model (Test)</button></li>
    </ul>
  </div>

  <div id="mainContent">
    <div class="content-header">
      <h1 id="activeTabTitle">Bảng Giá Model (VNĐ)</h1>
      <div>
        <span class="badge badge-success">VTeen Suite Active</span>
      </div>
    </div>

    <div class="content-body">
      <div id="pane-pricing" class="tab-pane active">
        <div class="card">
          <h3>Bảng Giá Model Chi Tiết (Đơn vị: VNĐ / 1k Tokens)</h3>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:16px;">
            Cấu hình đơn giá token đầu vào, đầu ra cho từng model. Giá này được hệ thống sử dụng tự động để tính toán chi phí và trừ số dư theo thời gian thực.
          </p>
          <div id="pricingTableContainer">Đang tải bảng giá...</div>
        </div>
      </div>

      <div id="pane-keys" class="tab-pane">
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
            <h3 style="margin:0;">Danh Sách API Keys Khách Hàng</h3>
            <button class="btn btn-primary" onclick="showCreateKeyModal()">+ Tạo Khóa Mới</button>
          </div>
          <div id="keysTableContainer">Đang tải danh sách khóa...</div>
        </div>
      </div>

      <div id="pane-auths" class="tab-pane">
        <div class="card">
          <h3>Thống Kê Token Theo Từng Tài Khoản (Auth Pool)</h3>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:16px;">
            Giám sát mức tiêu thụ token trên từng tài khoản upstream (Claude, Gemini, OpenAI, Kiro).
          </p>
          <div id="authsTableContainer">Đang tải dữ liệu tài khoản...</div>
        </div>
      </div>

      <div id="pane-kiro_oauth" class="tab-pane">
        <div class="card">
          <h3>Xác Thực Đăng Nhập Kiro (AWS SSO)</h3>
          <p style="color:var(--text-secondary);font-size:13px;">
            Tạo phiên đăng nhập AWS Builder ID / SSO để cấp phát token Kiro tự động vào pool.
          </p>
          <div style="margin-top:16px;">
            <button class="btn btn-primary" onclick="startKiroAuth()">Bắt Đầu Xác Thực AWS SSO</button>
          </div>
          <div id="kiroAuthResult" style="margin-top:16px;display:none;"></div>
        </div>
      </div>

      <div id="pane-logs" class="tab-pane">
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <h3 style="margin:0;">Nhật Ký Request & Check Lỗi Model Real-time</h3>
            <div>
              <button class="btn btn-secondary" onclick="refreshLogs()">Làm Mới</button>
              <button class="btn btn-danger" onclick="clearLogs()">Xóa Logs</button>
            </div>
          </div>
          <div id="logsTableContainer" style="max-height:600px;overflow-y:auto;">Đang kết nối luồng logs...</div>
        </div>
      </div>

      <div id="pane-telebot" class="tab-pane">
        <div class="card">
          <h3>Cấu Hình Bot Telegram & Cổng Thanh Toán SePay</h3>
          <div style="max-width:550px;">
            <div class="form-group">
              <label>Telegram Bot Token</label>
              <input type="password" id="cfgTeleToken" placeholder="123456:ABC-DEF...">
            </div>
            <div class="form-group">
              <label>Telegram Admin Chat ID</label>
              <input type="text" id="cfgTeleAdminID" placeholder="123456789">
            </div>
            <div class="form-group">
              <label>SePay API Token</label>
              <input type="password" id="cfgSePayToken" placeholder="SePay API Key">
            </div>
            <button class="btn btn-primary" onclick="saveTelebotConfig()">Lưu Cấu Hình</button>
          </div>
        </div>
      </div>

      <div id="pane-autoevent" class="tab-pane">
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
            <h3 style="margin:0;">Telegram Auto Event Userbot Subsystem</h3>
            <div id="autoEventStatusPill"><span class="badge badge-success">Sẵn sàng</span></div>
          </div>
          <p style="color:var(--text-secondary);font-size:13px;">
            Tự động theo dõi channel sự kiện và click button nhận quota vòng quay theo luồng sub-30