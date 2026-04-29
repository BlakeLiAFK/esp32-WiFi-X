// HTTP Basic Auth：仅 STA 模式默认开启
// SoftAP 模式默认免认证（首次配网；除非 Kconfig 强制开启）

#include "prov_internal.h"
#include "sdkconfig.h"

#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"

static const char *TAG = "wifix.auth";

#define AUTH_HEADER_NAME "Authorization"
#define WWW_AUTH_VALUE   "Basic realm=\"WiFi-X\", charset=\"UTF-8\""
#define AUTH_FAIL_DELAY_MS  300

// 解析并校验 Authorization: Basic 头；成功填充 user/pass 返回 true
static bool parse_basic(const char *header, char *user, size_t ucap, char *pass, size_t pcap)
{
    if (!header) return false;
    while (*header == ' ') header++;
    if (strncasecmp(header, "Basic ", 6) != 0) return false;
    const char *b64 = header + 6;
    while (*b64 == ' ') b64++;

    size_t b64_len = strlen(b64);
    if (b64_len == 0 || b64_len > 200) return false;

    unsigned char dec[160];
    size_t dec_len = 0;
    int rc = mbedtls_base64_decode(dec, sizeof(dec) - 1, &dec_len,
                                    (const unsigned char *)b64, b64_len);
    if (rc != 0) return false;
    if (dec_len >= sizeof(dec) - 1) return false;
    dec[dec_len] = 0;

    // 解码后内容里如果有 NUL 字节，可能让 strchr/strlcpy 截断匹配 — 拒绝
    if (memchr(dec, 0, dec_len) != NULL) return false;

    char *colon = strchr((char *)dec, ':');
    if (!colon) return false;
    *colon = 0;
    size_t ulen = strlen((char *)dec);
    size_t plen = strlen(colon + 1);
    if (ulen >= ucap || plen >= pcap) return false;  // 截断即拒绝
    memcpy(user, dec, ulen + 1);
    memcpy(pass, colon + 1, plen + 1);
    return true;
}

bool prov_auth_check(httpd_req_t *req, bool softap)
{
    if (softap && !prov_rt()->require_auth_in_ap) return true;

    char hdr[256];
    if (httpd_req_get_hdr_value_str(req, AUTH_HEADER_NAME, hdr, sizeof(hdr)) != ESP_OK) {
        return false;
    }
    char user[WIFIX_USER_MAX] = {0};
    char pass[WIFIX_PASS_MAX] = {0};
    if (!parse_basic(hdr, user, sizeof(user), pass, sizeof(pass))) {
        // 格式错误也加延迟，避免被用作探测
        vTaskDelay(pdMS_TO_TICKS(AUTH_FAIL_DELAY_MS));
        return false;
    }

    bool ok = prov_storage_check_credentials(user, pass);
    if (!ok) {
        ESP_LOGW(TAG, "登录失败 user=%s", user);
        vTaskDelay(pdMS_TO_TICKS(AUTH_FAIL_DELAY_MS));
    }
    return ok;
}

void prov_auth_send_401(httpd_req_t *req)
{
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", WWW_AUTH_VALUE);
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "Authentication required");
}
