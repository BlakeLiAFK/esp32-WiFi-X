// HTTP handler：AP/STA 共用同一份网页和 API
//
// 路由：
//   GET  /            配网/管理页（HTML）
//   GET  /info        模式与状态 JSON
//   GET  /scan        SoftAP 模式下返回缓存扫描结果
//   GET  /list        已存网络 SSID 列表（仅 SSID）
//   POST /add         body: ssid=...&pass=...
//   POST /remove      body: ssid=...
//   POST /clear       清空所有凭证（明确动作）
//   POST /done        SoftAP：保存并重启切 STA；STA：仅返回 OK
//   POST /change_pw   body: user=...&pass=...

#include "prov_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "wifix.http";

extern const char prov_page_start[] asm("_binary_prov_page_html_start");
extern const char prov_page_end[]   asm("_binary_prov_page_html_end");

// ---- 扫描缓存（SoftAP 用） ----
#define SCAN_CACHE_MAX 16
static prov_scan_entry_t s_scan[SCAN_CACHE_MAX];
static int s_scan_n;

void prov_set_scan_cache(const prov_scan_entry_t *list, int n)
{
    if (n > SCAN_CACHE_MAX) n = SCAN_CACHE_MAX;
    if (n > 0) memcpy(s_scan, list, sizeof(prov_scan_entry_t) * n);
    s_scan_n = n;
}

int prov_get_scan_cache(prov_scan_entry_t *out, int cap)
{
    int n = s_scan_n < cap ? s_scan_n : cap;
    if (n > 0) memcpy(out, s_scan, sizeof(prov_scan_entry_t) * n);
    return n;
}

// ---- URL 工具 ----
static void url_decode(char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (*r == '+') { *w++ = ' '; r++; }
        else if (*r == '%' && r[1] && r[2]) {
            char hex[3] = {r[1], r[2], 0};
            *w++ = (char)strtol(hex, NULL, 16);
            r += 3;
        } else *w++ = *r++;
    }
    *w = 0;
}

static bool form_get(const char *body, const char *key, char *out, size_t cap)
{
    size_t klen = strlen(key);
    const char *p = body;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            const char *end = strchr(v, '&');
            size_t vl = end ? (size_t)(end - v) : strlen(v);
            if (vl >= cap) vl = cap - 1;
            memcpy(out, v, vl);
            out[vl] = 0;
            url_decode(out);
            return true;
        }
        const char *amp = strchr(p, '&');
        if (!amp) break;
        p = amp + 1;
    }
    return false;
}

// 读 body 必须基于 Content-Length，避免 buffer 写满后剩余字节留在 socket
// 被解析为下一个 HTTP 请求（绕过 401 等假象）
// 返回 >=0 实际读到字节数，<0 表示请求过大或读取失败（caller 应回 4xx 终止）
static int read_body(httpd_req_t *req, char *buf, int cap)
{
    int clen = req->content_len;
    if (clen <= 0) { buf[0] = 0; return 0; }
    if (clen >= cap) return -1;  // 拒绝超长 body

    int total = 0;
    while (total < clen) {
        int n = httpd_req_recv(req, buf + total, clen - total);
        if (n == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (n <= 0) return -1;
        total += n;
    }
    buf[total] = 0;
    return total;
}

static esp_err_t send_413(httpd_req_t *req)
{
    httpd_resp_set_status(req, "413 Payload Too Large");
    return httpd_resp_sendstr(req, "body too large");
}

// ---- JSON 转义（不含外层引号） ----
static int json_escape(const char *src, char *dst, int cap)
{
    if (cap <= 0) return 0;
    int j = 0;
    for (int i = 0; src[i]; i++) {
        unsigned char c = src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= cap) break;
            dst[j++] = '\\';
            dst[j++] = c;
        } else if (c < 0x20) {
            if (j + 6 >= cap) break;
            int w = snprintf(dst + j, cap - j, "\\u%04x", c);
            if (w != 6) break;  // 容量不足导致截断，停止避免破坏 JSON
            j += 6;
        } else {
            if (j + 1 >= cap) break;
            dst[j++] = c;
        }
    }
    dst[j] = 0;
    return j;
}

// ---- 鉴权封装 ----
typedef struct { httpd_req_t *req; bool softap; } ctx_t;

#define REQUIRE_AUTH(softap)                                        \
    do {                                                            \
        if (!prov_auth_check(req, softap)) {                        \
            prov_auth_send_401(req);                                \
            return ESP_OK;                                          \
        }                                                           \
    } while (0)

// ---- handlers ----

static esp_err_t h_root(httpd_req_t *req)
{
    bool softap = (bool)(uintptr_t)req->user_ctx;
    REQUIRE_AUTH(softap);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, prov_page_start, prov_page_end - prov_page_start);
}

static esp_err_t h_captive_404(httpd_req_t *req, httpd_err_code_t err)
{
    // SoftAP 模式：所有未知路径返回配网页（captive portal 命中）
    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, prov_page_start, prov_page_end - prov_page_start);
}

static esp_err_t h_info(httpd_req_t *req)
{
    bool softap = (bool)(uintptr_t)req->user_ctx;
    REQUIRE_AUTH(softap);

    char user[WIFIX_USER_MAX] = "";
    prov_storage_get_username(user, sizeof(user));
    char user_esc[WIFIX_USER_MAX * 2] = "";
    json_escape(user, user_esc, sizeof(user_esc));

    const char *cur = prov_sta_current_ssid();
    char cur_esc[WIFIX_SSID_MAX * 2] = "";
    if (cur) json_escape(cur, cur_esc, sizeof(cur_esc));

    char buf[256];
    int len = snprintf(buf, sizeof(buf),
        "{\"mode\":\"%s\",\"state\":%d,\"user\":\"%s\",\"current\":\"%s\",\"rssi\":%d,\"count\":%d,\"max\":%d}",
        softap ? "ap" : "sta",
        (int)wifix_state(),
        user_esc,
        cur ? cur_esc : "",
        wifix_rssi(),
        prov_storage_count(),
        prov_rt()->max_networks);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, len);
}

static esp_err_t h_scan(httpd_req_t *req)
{
    bool softap = (bool)(uintptr_t)req->user_ctx;
    REQUIRE_AUTH(softap);

    char *body = malloc(2048);
    if (!body) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "no mem");
    }
    int len = snprintf(body, 2048, "{\"aps\":[");
    for (int i = 0; i < s_scan_n; i++) {
        char esc[WIFIX_SSID_MAX * 2];
        json_escape(s_scan[i].ssid, esc, sizeof(esc));
        len += snprintf(body + len, 2048 - len, "%s{\"ssid\":\"%s\",\"rssi\":%d,\"auth\":%d}",
                        i ? "," : "", esc, s_scan[i].rssi, s_scan[i].authmode);
    }
    len += snprintf(body + len, 2048 - len, "]}");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, body, len);
    free(body);
    return ESP_OK;
}

static esp_err_t h_list(httpd_req_t *req)
{
    bool softap = (bool)(uintptr_t)req->user_ctx;
    REQUIRE_AUTH(softap);

    int max_n = prov_rt()->max_networks;
    prov_creds_t *list = calloc(max_n, sizeof(prov_creds_t));
    if (!list) return httpd_resp_sendstr(req, "{\"items\":[]}");
    int n = 0;
    prov_storage_load_all(list, max_n, &n);

    char *body = malloc(2048);
    if (!body) { free(list); return httpd_resp_sendstr(req, "{\"items\":[]}"); }
    int len = snprintf(body, 2048, "{\"items\":[");
    const char *cur = prov_sta_current_ssid();
    for (int i = 0; i < n; i++) {
        char esc[WIFIX_SSID_MAX * 2];
        json_escape(list[i].ssid, esc, sizeof(esc));
        bool current = cur && strcmp(cur, list[i].ssid) == 0;
        len += snprintf(body + len, 2048 - len, "%s{\"ssid\":\"%s\",\"current\":%s}",
                        i ? "," : "", esc, current ? "true" : "false");
    }
    len += snprintf(body + len, 2048 - len, "]}");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, body, len);
    free(body); free(list);
    return ESP_OK;
}

static esp_err_t h_add(httpd_req_t *req)
{
    bool softap = (bool)(uintptr_t)req->user_ctx;
    REQUIRE_AUTH(softap);

    char buf[512];
    if (read_body(req, buf, sizeof(buf)) < 0) return send_413(req);
    char ssid[WIFIX_SSID_MAX] = {0};
    char pass[WIFIX_PASS_MAX] = {0};
    if (!form_get(buf, "ssid", ssid, sizeof(ssid)) || !ssid[0]) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "missing ssid");
    }
    form_get(buf, "pass", pass, sizeof(pass));

    esp_err_t err = prov_storage_add(ssid, pass);
    if (err == ESP_ERR_NO_MEM) {
        httpd_resp_set_status(req, "409 Conflict");
        return httpd_resp_sendstr(req, "已达上限");
    }
    if (err != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "save failed");
    }
    if (!softap) prov_sta_kick_rescan();
    return httpd_resp_sendstr(req, "ok");
}

static esp_err_t h_remove(httpd_req_t *req)
{
    bool softap = (bool)(uintptr_t)req->user_ctx;
    REQUIRE_AUTH(softap);

    char buf[256];
    if (read_body(req, buf, sizeof(buf)) < 0) return send_413(req);
    char ssid[WIFIX_SSID_MAX] = {0};
    if (!form_get(buf, "ssid", ssid, sizeof(ssid))) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "missing ssid");
    }
    esp_err_t err = prov_storage_remove(ssid);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "not found");
    }
    if (!softap) prov_sta_kick_rescan();
    return httpd_resp_sendstr(req, "ok");
}

static esp_err_t h_clear(httpd_req_t *req)
{
    bool softap = (bool)(uintptr_t)req->user_ctx;
    REQUIRE_AUTH(softap);
    prov_storage_clear_all();
    if (!softap) prov_sta_kick_rescan();
    return httpd_resp_sendstr(req, "ok");
}

static void delayed_restart(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

static esp_err_t h_done(httpd_req_t *req)
{
    bool softap = (bool)(uintptr_t)req->user_ctx;
    REQUIRE_AUTH(softap);
    httpd_resp_sendstr(req, "ok, rebooting");
    if (softap) {
        ESP_LOGI(TAG, "用户点击完成，重启切 STA");
        xTaskCreate(delayed_restart, "wifix_rst", 2048, NULL, 5, NULL);
    }
    return ESP_OK;
}

static esp_err_t h_change_pw(httpd_req_t *req)
{
    bool softap = (bool)(uintptr_t)req->user_ctx;
    REQUIRE_AUTH(softap);
    char buf[256];
    if (read_body(req, buf, sizeof(buf)) < 0) return send_413(req);
    char user[WIFIX_USER_MAX] = {0};
    char pass[WIFIX_PASS_MAX] = {0};
    if (!form_get(buf, "user", user, sizeof(user)) || !user[0]) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "missing user");
    }
    if (!form_get(buf, "pass", pass, sizeof(pass)) || !pass[0]) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "missing pass");
    }
    esp_err_t err = prov_storage_set_credentials(user, pass);
    if (err != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "save failed");
    }
    return httpd_resp_sendstr(req, "ok");
}

void prov_http_register(httpd_handle_t srv, bool softap)
{
    void *ctx = (void *)(uintptr_t)softap;

    httpd_uri_t uris[] = {
        {.uri = "/",          .method = HTTP_GET,  .handler = h_root,      .user_ctx = ctx},
        {.uri = "/info",      .method = HTTP_GET,  .handler = h_info,      .user_ctx = ctx},
        {.uri = "/scan",      .method = HTTP_GET,  .handler = h_scan,      .user_ctx = ctx},
        {.uri = "/list",      .method = HTTP_GET,  .handler = h_list,      .user_ctx = ctx},
        {.uri = "/add",       .method = HTTP_POST, .handler = h_add,       .user_ctx = ctx},
        {.uri = "/remove",    .method = HTTP_POST, .handler = h_remove,    .user_ctx = ctx},
        {.uri = "/clear",     .method = HTTP_POST, .handler = h_clear,     .user_ctx = ctx},
        {.uri = "/done",      .method = HTTP_POST, .handler = h_done,      .user_ctx = ctx},
        {.uri = "/change_pw", .method = HTTP_POST, .handler = h_change_pw, .user_ctx = ctx},
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_register_uri_handler(srv, &uris[i]);
    }
    if (softap) {
        httpd_register_err_handler(srv, HTTPD_404_NOT_FOUND, h_captive_404);
    }
}
