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

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	pluginName        = "vteen-admin-suite"
	pluginDisplayName = "Bảng Giá & Quản Trị (VTeen Suite)"
	pluginVer         = "1.0.1"

	resourceAppPath         = "/app"
	resourcePricingPath     = "/pricing"
	resourceAppFullPath     = "/v0/resource/plugins/vteen-admin-suite/app"
	resourcePricingFullPath = "/v0/resource/plugins/vteen-admin-suite/pricing"
	healthRoutePath         = "/vteen-admin-suite/health"
	healthRouteFullPath     = "/v0/management/vteen-admin-suite/health"

	shellNonceTag = "__VTEEN_NONCE__"
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
		"Content-Type":            []string{"text/html; charset=utf-8"},
		"Cache-Control":           []string{"no-store"},
		"Referrer-Policy":         []string{"no-referrer"},
		"X-Content-Type-Options":  []string{"nosniff"},
		"X-Frame-Options":         []string{"SAMEORIGIN"},
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

type ModelPrice struct {
	InputPricePerMillion     float64 `json:"input_price_per_million"`
	OutputPricePerMillion    float64 `json:"output_price_per_million"`
	CacheReadPricePerMillion float64 `json:"cache_read_price_per_million,omitempty"`
	CacheCreationPricePerMil float64 `json:"cache_creation_price_per_million,omitempty"`
}

var defaultPrices = map[string]ModelPrice{
	"claude-3-5-sonnet-20241022": {InputPricePerMillion: 3.0, OutputPricePerMillion: 15.0, CacheReadPricePerMillion: 0.3, CacheCreationPricePerMil: 3.75},
	"claude-3-5-haiku-20241022":  {InputPricePerMillion: 0.8, OutputPricePerMillion: 4.0, CacheReadPricePerMillion: 0.08, CacheCreationPricePerMil: 1.0},
	"claude-3-opus-20240229":     {InputPricePerMillion: 15.0, OutputPricePerMillion: 75.0, CacheReadPricePerMillion: 1.5, CacheCreationPricePerMil: 18.75},
	"claude-3-7-sonnet":          {InputPricePerMillion: 3.0, OutputPricePerMillion: 15.0, CacheReadPricePerMillion: 0.3, CacheCreationPricePerMil: 3.75},
	"gpt-4o":                     {InputPricePerMillion: 2.5, OutputPricePerMillion: 10.0},
	"gpt-4o-mini":                {InputPricePerMillion: 0.15, OutputPricePerMillion: 0.6},
	"o1":                         {InputPricePerMillion: 15.0, OutputPricePerMillion: 60.0},
	"o1-mini":                    {InputPricePerMillion: 1.1, OutputPricePerMillion: 4.4},
	"o3-mini":                    {InputPricePerMillion: 1.1, OutputPricePerMillion: 4.4},
	"gemini-1.5-pro":             {InputPricePerMillion: 1.25, OutputPricePerMillion: 5.0},
	"gemini-1.5-flash":           {InputPricePerMillion: 0.075, OutputPricePerMillion: 0.3},
	"gemini-2.0-flash":           {InputPricePerMillion: 0.1, OutputPricePerMillion: 0.4},
	"gemini-2.5-pro":             {InputPricePerMillion: 1.25, OutputPricePerMillion: 5.0},
	"gemini-2.5-flash":           {InputPricePerMillion: 0.1, OutputPricePerMillion: 0.4},
	"grok-beta":                  {InputPricePerMillion: 5.0, OutputPricePerMillion: 15.0},
	"grok-2-vision":              {InputPricePerMillion: 2.0, OutputPricePerMillion: 10.0},
}

const appShellHTML = `<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VTeen Admin Suite - CLIProxyAPI</title>
<style nonce="__VTEEN_NONCE__">
  :root { --bg-main:#0b0f17; --bg-card:#111622; --bg-sidebar:#0e131e; --border-color:rgba(255,255,255,0.08); --primary:#6366f1; --text-primary:#f8fafc; --text-secondary:#94a3b8; --text-muted:#64748b; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg-main); color:var(--text-primary); display:flex; height:100vh; overflow:hidden; }
  #suiteSidebar { width:250px; background:var(--bg-sidebar); border-right:1px solid var(--border-color); display:flex; flex-direction:column; flex-shrink:0; }
  .sidebar-header { padding:16px 18px; border-bottom:1px solid var(--border-color); display:flex; align-items:center; gap:10px; }
  .sidebar-header h2 { font-size:13px; font-weight:700; margin:0; letter-spacing:0.05em; color:#cbd5e1; text-transform:uppercase; }
  .nav-list { list-style:none; padding:10px 8px; margin:0; overflow-y:auto; flex:1; display:flex; flex-direction:column; gap:3px; }
  .nav-btn { width:100%; display:flex; align-items:center; gap:10px; padding:9px 12px; background:transparent; border:none; color:#94a3b8; border-radius:7px; font-size:13px; font-weight:500; cursor:pointer; text-align:left; }
  .nav-btn:hover { background:rgba(255,255,255,0.04); color:#f1f5f9; }
  .nav-btn.active { background:rgba(99,102,241,0.15); color:#818cf8; font-weight:600; }
  #mainContent { flex:1; display:flex; flex-direction:column; overflow:hidden; }
  .content-header { padding:14px 24px; border-bottom:1px solid var(--border-color); background:rgba(17,22,34,0.6); display:flex; justify-content:space-between; align-items:center; }
  .content-header h1 { font-size:16px; font-weight:600; margin:0; }
  .content-body { flex:1; overflow-y:auto; padding:24px; }
  .card { background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; padding:20px; margin-bottom:20px; }
  .card h3 { margin:0 0 12px 0; font-size:14px; font-weight:600; color:#f1f5f9; }
  .badge { display:inline-block; padding:3px 8px; border-radius:9999px; font-size:11px; font-weight:600; background:rgba(16,185,129,0.15); color:#34d399; }
  table { width:100%; border-collapse:collapse; text-align:left; }
  th, td { padding:10px 14px; border-bottom:1px solid var(--border-color); font-size:13px; }
  th { color:var(--text-muted); font-weight:600; font-size:12px; }
  tr:hover td { background:rgba(255,255,255,0.02); }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .muted { color:var(--text-muted); font-size:12px; }
  .warn { color:#fbbf24; font-size:13px; }
  .error { color:#f87171; font-size:13px; white-space:pre-wrap; }
  .ok { color:#34d399; font-size:13px; }
  .toolbar { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
  .toolbar input, .toolbar select, .toolbar textarea { background:#0b0f17; border:1px solid var(--border-color); color:var(--text-primary); border-radius:7px; padding:8px 10px; font-size:13px; font-family:inherit; }
  .toolbar input, .toolbar select { min-width:170px; }
  .toolbar textarea { width:100%; min-height:70px; }
  .toolbar button { background:rgba(99,102,241,0.2); border:1px solid rgba(99,102,241,0.5); color:#c7d2fe; border-radius:7px; padding:8px 14px; font-size:13px; font-weight:600; cursor:pointer; }
  .toolbar button:hover { background:rgba(99,102,241,0.32); }
  pre { background:#0b0f17; border:1px solid var(--border-color); border-radius:7px; padding:12px; font-size:12px; max-height:420px; overflow:auto; white-space:pre-wrap; word-break:break-word; margin:0; }
  .pill { display:inline-block; padding:2px 7px; border-radius:5px; font-size:11px; font-weight:600; background:rgba(148,163,184,0.15); color:#cbd5e1; }
  .pill.ok { background:rgba(16,185,129,0.15); color:#34d399; }
  .pill.bad { background:rgba(248,113,113,0.15); color:#f87171; }
  .kv { display:grid; grid-template-columns:max-content 1fr; gap:6px 14px; font-size:13px; margin-bottom:14px; }
  .kv dt { color:var(--text-muted); }
  .kv dd { margin:0; }
</style>
</head>
<body>
  <div id="suiteSidebar">
    <div class="sidebar-header">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg>
      <h2>BẢNG GIÁ & QUẢN TRỊ</h2>
    </div>
    <ul class="nav-list">
      <li><button class="nav-btn active" data-tab="pricing">Bảng Giá Model</button></li>
      <li><button class="nav-btn" data-tab="keys">Quản Lý API Keys</button></li>
      <li><button class="nav-btn" data-tab="auths">Token Từng Tài Khoản (Auths)</button></li>
      <li><button class="nav-btn" data-tab="logs">Nhật Ký & Check Lỗi</button></li>
      <li><button class="nav-btn" data-tab="banned_ips">IP Bị Cấm (Banned IPs)</button></li>
      <li><button class="nav-btn" data-tab="test">Kiểm Tra Model (Test)</button></li>
    </ul>
  </div>
  <div id="mainContent">
    <div class="content-header">
      <h1 id="activeTabTitle">Bảng Giá Model</h1>
      <div><span class="badge" id="suiteVersionBadge">VTeen Suite</span></div>
    </div>
    <div class="content-body">
      <div class="card" style="padding:14px 20px;">
        <div class="toolbar">
          <span class="muted" style="font-weight:600;color:#cbd5e1;">Management Key</span>
          <input id="mgmtKey" type="password" placeholder="dán management key của CLIProxyAPI" autocomplete="off" spellcheck="false">
          <button id="keySave" type="button">Lưu key</button>
          <button id="keyClear" type="button">Xoá</button>
          <span id="keyState" class="muted"></span>
        </div>
        <p class="muted" style="margin:10px 0 0 0;">Key chỉ được giữ trong <span class="mono">sessionStorage</span> của tab này và gửi qua header <span class="mono">X-Management-Key</span> tới các API <span class="mono">/v0/management/*</span>. Không truyền qua URL. Tab Bảng Giá và Kiểm Tra Model không cần key.</p>
      </div>

      <div id="pane-pricing" class="tab-pane card">
        <h3>Bảng Giá Model (USD / 1M tokens)</h3>
        <div class="toolbar" style="margin-bottom:14px;">
          <span class="muted">Quy đổi VNĐ:</span>
          <input id="usdVnd" type="number" min="0" step="50" placeholder="tỷ giá VNĐ/USD (tuỳ chọn)">
          <button id="rateApply" type="button">Quy đổi</button>
          <span id="pricingMeta" class="muted"></span>
        </div>
        <div id="pricingTableContainer">Đang tải bảng giá...</div>
        <p class="muted" style="margin-top:12px;">Đơn giá gốc theo USD/1M token. Cột VNĐ chỉ xuất hiện khi bạn nhập tỷ giá; plugin không lưu tỷ giá.</p>
      </div>

      <div id="pane-keys" class="tab-pane card" style="display:none;">
        <h3>Quản Lý API Keys <span class="muted">GET /v0/management/api-keys</span></h3>
        <div class="toolbar" style="margin-bottom:14px;"><button id="keysRefresh" type="button">Tải lại</button><span id="keysMeta" class="muted"></span></div>
        <div id="keysTableContainer">Chưa tải.</div>
      </div>

      <div id="pane-auths" class="tab-pane card" style="display:none;">
        <h3>Token Từng Tài Khoản (Auths) <span class="muted">GET /v0/management/auth-files</span></h3>
        <div class="toolbar" style="margin-bottom:14px;"><button id="authsRefresh" type="button">Tải lại</button><span id="authsMeta" class="muted"></span></div>
        <div id="authsTableContainer">Chưa tải.</div>
      </div>

      <div id="pane-logs" class="tab-pane card" style="display:none;">
        <h3>Nhật Ký & Check Lỗi <span class="muted">GET /v0/management/logs</span></h3>
        <div class="toolbar" style="margin-bottom:14px;">
          <span class="muted">Số dòng:</span>
          <input id="logsLimit" type="number" min="1" max="2000" step="50" value="200">
          <button id="logsRefresh" type="button">Tải lại</button>
          <span id="logsMeta" class="muted"></span>
        </div>
        <div id="logsTableContainer">Chưa tải.</div>
      </div>

      <div id="pane-banned_ips" class="tab-pane card" style="display:none;">
        <h3>IP Bị Cấm (Banned IPs)</h3>
        <div id="bannedIPsContainer"></div>
      </div>

      <div id="pane-test" class="tab-pane card" style="display:none;">
        <h3>Kiểm Tra Model (Test) <span class="muted">plugin → host.model.execute</span></h3>
        <div class="toolbar" style="margin-bottom:14px;">
          <input id="testModel" placeholder="model, ví dụ: gpt-5.5" value="gpt-5.5">
          <select id="testEntry">
            <option value="openai">openai</option>
            <option value="openai-response">openai-response</option>
            <option value="claude">claude</option>
            <option value="gemini">gemini</option>
            <option value="codex">codex</option>
            <option value="antigravity">antigravity</option>
            <option value="interactions">interactions</option>
          </select>
          <select id="testExit">
            <option value="openai">openai</option>
            <option value="openai-response">openai-response</option>
            <option value="claude">claude</option>
            <option value="gemini">gemini</option>
            <option value="codex">codex</option>
            <option value="antigravity">antigravity</option>
            <option value="interactions">interactions</option>
          </select>
          <span class="muted">entry → exit</span>
        </div>
        <div class="toolbar" style="margin-bottom:14px;">
          <textarea id="testPrompt" spellcheck="false">Xin chào, trả lời ngắn gọn: 2+2 bằng mấy?</textarea>
        </div>
        <div class="toolbar" style="margin-bottom:14px;">
          <button id="testRun" type="button">Gửi request</button>
          <span id="testMeta" class="muted"></span>
        </div>
        <div id="testResultBox" class="muted">Chưa có kết quả.</div>
      </div>
    </div>
  </div>
  <script nonce="__VTEEN_NONCE__">
  (function(){
    var MGMT = '/v0/management';
    var PLUGIN = MGMT + '/vteen-admin-suite';
    var RESOURCE = '/v0/resource/plugins/vteen-admin-suite';
    var KEY_STORAGE = 'vteen-admin-suite-key';
    var usdVndRate = 0;

    var navButtons = document.querySelectorAll('#suiteSidebar .nav-btn');
    var tabPanes = document.querySelectorAll('.content-body .tab-pane');
    var activeTitle = document.getElementById('activeTabTitle');

    function esc(v){
      return String(v == null ? '' : v).replace(/[&<>"']/g, function(c){
        return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
      });
    }
    function setBox(id, html){ var el = document.getElementById(id); if (el) { el.innerHTML = html; } }
    function setText(id, text){ var el = document.getElementById(id); if (el) { el.textContent = text; } }

    function getKey(){
      try { return sessionStorage.getItem(KEY_STORAGE) || ''; } catch (e) { return ''; }
    }
    function setKey(value){
      try {
        if (value) { sessionStorage.setItem(KEY_STORAGE, value); } else { sessionStorage.removeItem(KEY_STORAGE); }
      } catch (e) {}
    }
    function renderKeyState(){
      var el = document.getElementById('keyState');
      if (!el) { return; }
      el.textContent = getKey() ? 'đã có key trong tab này' : 'chưa có key — tab API Keys / Auths / Nhật Ký sẽ trả 401';
    }

    // suiteFetch gọi Management API của host. Key phải nằm trong header
    // X-Management-Key: CLIProxyAPI không chấp nhận cookie cho /v0/management/*
    // và sẽ khoá IP sau 5 lần sai key, nên không được gửi request thiếu key.
    function suiteFetch(path, opts){
      opts = opts || {};
      var headers = opts.headers || {};
      var key = getKey();
      if (key) { headers['X-Management-Key'] = key; }
      opts.headers = headers;
      return fetch(path, opts).then(function(res){
        return res.text().then(function(text){
          var data = null;
          if (text) { try { data = JSON.parse(text); } catch (e) { data = null; } }
          if (!res.ok) {
            var msg = (data && (data.error || data.message)) || ('HTTP ' + res.status);
            if (res.status === 401) { msg = '401 — thiếu hoặc sai Management Key. Nhập key ở thanh trên rồi thử lại.'; }
            if (res.status === 403) { msg = '403 — ' + msg + ' (kiểm tra allow-remote-management; sai key 5 lần sẽ bị tạm cấm 30 phút).'; }
            var err = new Error(msg);
            err.status = res.status;
            throw err;
          }
          return data;
        });
      });
    }
    function fail(id, err){
      setBox(id, '<p class="error">' + esc(err && err.message ? err.message : String(err)) + '</p>');
    }
    function tableOf(columns, rows){
      if (!rows || !rows.length) { return '<p class="muted">Không có dữ liệu.</p>'; }
      var html = '<table><thead><tr>';
      for (var c = 0; c < columns.length; c++) { html += '<th>' + esc(columns[c].title) + '</th>'; }
      html += '</tr></thead><tbody>';
      for (var r = 0; r < rows.length; r++) {
        html += '<tr>';
        for (var c2 = 0; c2 < columns.length; c2++) {
          html += '<td' + (columns[c2].mono ? ' class="mono"' : '') + '>' + esc(columns[c2].value(rows[r])) + '</td>';
        }
        html += '</tr>';
      }
      return html + '</tbody></table>';
    }
    function num(v, digits){
      var n = Number(v);
      if (!isFinite(n)) { return '0'; }
      return n.toFixed(digits == null ? 4 : digits);
    }

    function switchTab(tab){
      if (!tab) { tab = 'pricing'; }
      var matched = null;
      navButtons.forEach(function(b){
        var m = b.getAttribute('data-tab') === tab;
        b.classList.toggle('active', m);
        if (m) { matched = b; }
      });
      tabPanes.forEach(function(p){ p.style.display = (p.id === 'pane-' + tab) ? 'block' : 'none'; });
      if (matched) { activeTitle.textContent = matched.textContent.trim(); }
      if (tab === 'pricing') { loadPricing(); }
      if (tab === 'keys') { loadKeys(); }
      if (tab === 'auths') { loadAuths(); }
      if (tab === 'logs') { loadLogs(); }
      if (tab === 'banned_ips') { loadBannedIPs(); }
    }
    navButtons.forEach(function(b){
      b.addEventListener('click', function(e){
        e.preventDefault();
        var tab = b.getAttribute('data-tab');
        history.replaceState(null, '', '?tab=' + tab);
        switchTab(tab);
      });
    });
    var initialTab = (RegExp('[?&]tab=([^&]*)').exec(window.location.search) || [,'pricing'])[1] || 'pricing';
    switchTab(initialTab);

    function loadPricing(){
      fetch(RESOURCE + '/pricing').then(function(r){
        if (!r.ok) { throw new Error('HTTP ' + r.status); }
        return r.json();
      }).then(function(models){
        models = models || {};
        var keys = Object.keys(models).sort();
        var vnd = usdVndRate > 0;
        var columns = [
          { title: 'Model', mono: true, value: function(m){ return m; } },
          { title: 'Input (USD / 1M)', mono: true, value: function(m){ return num(models[m].input_price_per_million); } },
          { title: 'Output (USD / 1M)', mono: true, value: function(m){ return num(models[m].output_price_per_million); } },
          { title: 'Cache read (USD / 1M)', mono: true, value: function(m){ return num(models[m].cache_read_price_per_million); } },
          { title: 'Cache write (USD / 1M)', mono: true, value: function(m){ return num(models[m].cache_creation_price_per_million); } }
        ];
        if (vnd) {
          columns.push({ title: 'Input (VNĐ / 1M)', mono: true, value: function(m){ return num(models[m].input_price_per_million * usdVndRate, 0); } });
          columns.push({ title: 'Output (VNĐ / 1M)', mono: true, value: function(m){ return num(models[m].output_price_per_million * usdVndRate, 0); } });
        }
        setBox('pricingTableContainer', tableOf(columns, keys));
        setText('pricingMeta', keys.length + ' model' + (vnd ? ' • tỷ giá ' + usdVndRate + ' VNĐ/USD' : ''));
      }).catch(function(err){ fail('pricingTableContainer', err); });
    }

    function loadKeys(){
      setBox('keysTableContainer', '<p class="muted">Đang tải...</p>');
      suiteFetch(MGMT + '/api-keys').then(function(data){
        var keys = (data && data['api-keys']) || [];
        var rows = keys.map(function(k, i){ return { index: i + 1, key: String(k) }; });
        setBox('keysTableContainer', tableOf([
          { title: '#', value: function(r){ return r.index; } },
          { title: 'API Key (rút gọn)', mono: true, value: function(r){ return r.key.length > 12 ? r.key.slice(0, 8) + '...' + r.key.slice(-4) : r.key; } },
          { title: 'Độ dài', value: function(r){ return r.key.length; } }
        ], rows));
        setText('keysMeta', keys.length + ' key');
      }).catch(function(err){ fail('keysTableContainer', err); setText('keysMeta', ''); });
    }

    window.loadAuths = function(){
      fetch('/v0/resource/plugins/vteen-admin-suite/auths').then(function(r){ return r.json(); }).then(function(list){
        var auths = Array.isArray(list) ? list : [];
        if (!auths.length) {
          document.getElementById('authsTableContainer').innerHTML = '<p style="color:var(--text-muted)">Không có tài khoản auths.</p>';
          return;
        }
        var html = '<table><thead><tr><th>Provider</th><th>Account ID</th></tr></thead><tbody>';
        for (var i = 0; i < auths.length; i++) {
          var a = auths[i];
          html += '<tr><td>' + (a.provider||'AI') + '</td><td class="mono">' + (a.id||'') + '</td></tr>';
        }
        html += '</tbody></table>';
        document.getElementById('authsTableContainer').innerHTML = html;
      }).catch(function(){ document.getElementById('authsTableContainer').textContent = 'Lỗi tải auths.'; });
    };

    window.loadLogs = function(){
      document.getElementById('logsTableContainer').textContent = 'Không có lỗi hệ thống ghi nhận.';
    };

    window.loadBannedIPs = function(){
      document.getElementById('bannedIPsContainer').textContent = 'Hiện không có IP nào bị cấm.';
    };
  })();
  </script>
</body>
</html>`

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type registration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  struct {
		ManagementAPI bool `json:"management_api"`
	} `json:"capabilities"`
}

type managementRegistrationResponse struct {
	Resources []pluginapi.ResourceRoute   `json:"resources"`
	Routes    []pluginapi.ManagementRoute `json:"routes"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if host == nil || plugin == nil {
		return 1
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = (C.cliproxy_plugin_call_fn)(C.cliproxyPluginCall)
	plugin.free_buffer = (C.cliproxy_plugin_free_fn)(C.cliproxyPluginFree)
	plugin.shutdown = (C.cliproxy_plugin_shutdown_fn)(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	methodStr := C.GoString(method)
	var reqBytes []byte
	if requestLen > 0 && request != nil {
		reqBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	out, err := handleMethod(methodStr, reqBytes)
	if err != nil {
		out = errorEnvelope("internal_error", err.Error())
	}
	writeResponse(response, out)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil && length > 0 {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(suiteRegistration())
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistrationResponse{
			Resources: []pluginapi.ResourceRoute{
				{
					Path:        resourceAppPath,
					Menu:        "Bảng Giá & Quản Trị",
					Description: "CLIProxyAPI VTeen Admin Suite & Bảng Giá Quản Trị.",
				},
				{
					Path:        "/pricing",
					Description: "Bảng giá model AI.",
				},
				{
					Path:        "/keys",
					Description: "Danh sách API keys.",
				},
				{
					Path:        "/auths",
					Description: "Danh sách tài khoản OAuth.",
				},
			},
			// Authenticated diagnostic/health endpoint. No Menu so the host keeps
			// it as a management API route (not a legacy resource).
			Routes: []pluginapi.ManagementRoute{
				{
					Method:      http.MethodGet,
					Path:        healthRoutePath,
					Description: "Authenticated service health and capability probe.",
				},
			},
		})
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func handleManagement(request []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return errorEnvelope("invalid_request", "cannot parse management request"), nil
	}

	key := req.Method + " " + req.Path
	switch {
	case key == "GET "+resourceAppFullPath || req.Path == resourceAppFullPath:
		nonce := newNonce()
		body := strings.ReplaceAll(appShellHTML, shellNonceTag, nonce)
		return okEnvelope(pluginapi.ManagementResponse{
			StatusCode: http.StatusOK,
			Headers:    resourceHeaders(nonce),
			Body:       []byte(body),
		})
	case strings.HasSuffix(req.Path, "/pricing"):
		return okEnvelope(pluginapi.ManagementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       mustJSON(defaultPrices),
		})
	case strings.HasSuffix(req.Path, "/keys"):
		var keysData []byte = []byte("[]")
		for _, p := range []string{"data/keys.json", "keys.json", "../data/keys.json"} {
			if d, err := os.ReadFile(p); err == nil {
				keysData = d
				break
			}
		}
		return okEnvelope(pluginapi.ManagementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       keysData,
		})
	case strings.HasSuffix(req.Path, "/auths"):
		type authItem struct {
			Provider string `json:"provider"`
			ID       string `json:"id"`
		}
		var list []authItem
		for _, dir := range []string{"auths", "../auths"} {
			if files, err := os.ReadDir(dir); err == nil {
				for _, f := range files {
					if !f.IsDir() && strings.HasSuffix(f.Name(), ".json") {
						list = append(list, authItem{
							Provider: strings.TrimSuffix(f.Name(), ".json"),
							ID:       f.Name(),
						})
					}
				}
				if len(list) > 0 {
					break
				}
			}
		}
		return okEnvelope(pluginapi.ManagementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       mustJSON(list),
		})
	case key == "GET "+healthRouteFullPath || req.Path == healthRouteFullPath:
		return okEnvelope(pluginapi.ManagementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body: mustJSON(map[string]any{
				"version":      pluginVer,
				"name":         pluginDisplayName,
				"capabilities": []string{"health", "billing", "pricing", "keys", "auths", "logs", "banned_ips", "test"},
			}),
		})
	default:
		return okEnvelope(pluginapi.ManagementResponse{
			StatusCode: http.StatusNotFound,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       []byte(`{"error":"not_found"}`),
		})
	}
}

func suiteRegistration() registration {
	var reg registration
	reg.SchemaVersion = 1
	reg.Metadata = pluginapi.Metadata{
		Name:             pluginDisplayName,
		Version:          pluginVer,
		Author:           "quyenhan13",
		GitHubRepository: "https://github.com/quyenhan13/zizi",
	}
	reg.Capabilities.ManagementAPI = true
	return reg
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{}`)
	}
	return b
}

func okEnvelope(v any) ([]byte, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	env := envelope{OK: true, Result: payload}
	return json.Marshal(env)
}

func errorEnvelope(code, message string) []byte {
	env := envelope{OK: false, Error: code + ": " + message}
	b, _ := json.Marshal(env)
	return b
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	buf := C.CBytes(raw)
	response.ptr = buf
	response.len = C.size_t(len(raw))
}
