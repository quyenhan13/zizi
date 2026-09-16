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
	"os"
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
<title>Bảng Giá & Quản Trị - CLIProxyAPI</title>
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
  .mono { font-family:monospace; }
</style>
</head>
<body>
  <div id="suiteSidebar">
    <div class="sidebar-header">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg>
      <h2>BẢNG GIÁ & QUẢN TRỊ</h2>
    </div>
    <ul class="nav-list">
      <li><button class="nav-btn active" data-tab="pricing">Bảng Giá Model (VNĐ)</button></li>
      <li><button class="nav-btn" data-tab="keys">Quản Lý & Tạo API Keys</button></li>
      <li><button class="nav-btn" data-tab="auths">Token Từng Tài Khoản (Auths)</button></li>
      <li><button class="nav-btn" data-tab="logs">Nhật Ký & Check Lỗi</button></li>
      <li><button class="nav-btn" data-tab="banned_ips">IP Bị Cấm (Banned IPs)</button></li>
      <li><button class="nav-btn" data-tab="test">Kiểm Tra Model (Test)</button></li>
    </ul>
  </div>
  <div id="mainContent">
    <div class="content-header">
      <h1 id="activeTabTitle">Bảng Giá Model (VNĐ)</h1>
      <div><span class="badge">VTeen Suite Active</span></div>
    </div>
    <div class="content-body">
      <div id="pane-pricing" class="tab-pane card"><h3>Bảng Giá Model (Đơn vị: VNĐ / 1k tokens)</h3><div id="pricingTableContainer">Đang tải bảng giá...</div></div>
      <div id="pane-keys" class="tab-pane card" style="display:none;"><h3>API Keys</h3><div id="keysTableContainer">Đang tải...</div></div>
      <div id="pane-auths" class="tab-pane card" style="display:none;"><h3>Auth Accounts</h3><div id="authsTableContainer">Đang tải...</div></div>
      <div id="pane-logs" class="tab-pane card" style="display:none;"><h3>Logs</h3><div id="logsTableContainer">Đang tải...</div></div>
      <div id="pane-banned_ips" class="tab-pane card" style="display:none;"><h3>Banned IPs</h3><div id="bannedIPsContainer">Đang tải...</div></div>
      <div id="pane-test" class="tab-pane card" style="display:none;"><h3>Test Model</h3><div id="testResultBox">Chưa có kết quả.</div></div>
    </div>
  </div>
  <script nonce="__VTEEN_NONCE__">
  (function(){
    var navButtons = document.querySelectorAll('#suiteSidebar .nav-btn');
    var tabPanes = document.querySelectorAll('.content-body .tab-pane');
    var activeTitle = document.getElementById('activeTabTitle');
    function switchTab(tab){
      if (!tab) tab = 'pricing';
      var matched = null;
      navButtons.forEach(function(b){
        var m = b.getAttribute('data-tab') === tab;
        b.classList.toggle('active', m);
        if (m) matched = b;
      });
      tabPanes.forEach(function(p){ p.style.display = (p.id === 'pane-' + tab) ? 'block' : 'none'; });
      if (matched) activeTitle.textContent = matched.textContent.trim();
      if (tab === 'pricing') loadPricing();
      if (tab === 'keys') loadKeys();
      if (tab === 'auths') loadAuths();
      if (tab === 'logs') loadLogs();
      if (tab === 'banned_ips') loadBannedIPs();
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

    window.loadPricing = function(){
      fetch('/v0/resource/plugins/vteen-admin-suite/pricing').then(function(r){ return r.json(); }).then(function(models){
        var html = '<table><thead><tr><th>Tên Model</th><th>Input ($ / 1M)</th><th>Output ($ / 1M)</th><th>Cache Read</th><th>Cache Write</th></tr></thead><tbody>';
        var keys = Object.keys(models).sort();
        for (var i = 0; i < keys.length; i++){
          var k = keys[i];
          var it = models[k] || {};
          html += '<tr><td class="mono" style="font-weight:600;">' + k + '</td><td class="mono">$' + (it.input_price_per_million||0).toFixed(4) + '</td><td class="mono">$' + (it.output_price_per_million||0).toFixed(4) + '</td><td class="mono">$' + (it.cache_read_price_per_million||0).toFixed(4) + '</td><td class="mono">$' + (it.cache_creation_price_per_million||0).toFixed(4) + '</td></tr>';
        }
        html += '</tbody></table>';
        document.getElementById('pricingTableContainer').innerHTML = html;
      }).catch(function(e){ document.getElementById('pricingTableContainer').textContent = 'Lỗi tải bảng giá: ' + e.message; });
    };

    window.loadKeys = function(){
      fetch('/v0/resource/plugins/vteen-admin-suite/keys').then(function(r){ return r.json(); }).then(function(keys){
        var list = Array.isArray(keys) ? keys : [];
        if (!list.length) {
          document.getElementById('keysTableContainer').innerHTML = '<p style="color:var(--text-muted)">Chưa có key nào.</p>';
          return;
        }
        var html = '<table><thead><tr><th>Tên</th><th>Khóa</th></tr></thead><tbody>';
        for (var i = 0; i < list.length; i++) {
          var k = list[i];
          html += '<tr><td>' + (k.name||'Default') + '</td><td class="mono">' + (k.key ? k.key.substring(0, 15) + '...' : '') + '</td></tr>';
        }
        html += '</tbody></table>';
        document.getElementById('keysTableContainer').innerHTML = html;
      }).catch(function(){ document.getElementById('keysTableContainer').textContent = 'Lỗi tải keys.'; });
    };

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
					Path:        resourceApp,
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
					Path:        healthRoute,
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
