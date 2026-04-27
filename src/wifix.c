// 一站式入口
//
// 启动流程：
//   1. 加载配置（cfg > Kconfig 默认）
//   2. prov_storage_init（首次启动写入默认账密）
//   3. prov_storage_power_cycle_check：连续短电启动 N 次设 force flag
//   4. 决定模式：force flag 或 列表为空 → SoftAP；否则 STA
//   5. STA 模式连上后启 HTTP 管理界面（如启用）

#include "wifix.h"
#include "prov_internal.h"
#include "sdkconfig.h"

#include <string.h>

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "wifix";

static prov_runtime_t s_rt;
static volatile wifix_state_t s_state = WIFIX_STATE_BOOTING;
static wifix_event_cb_t s_cb;
static void *s_cb_user;
static httpd_handle_t s_sta_httpd;

const prov_runtime_t *prov_rt(void) { return &s_rt; }

void wifix_set_state(wifix_state_t st)
{
    s_state = st;
    if (s_cb) s_cb(st, s_cb_user);
}

wifix_state_t wifix_state(void) { return s_state; }

int wifix_rssi(void) { return prov_sta_rssi(); }

const char *wifix_current_ssid(void) { return prov_sta_current_ssid(); }

void wifix_set_event_cb(wifix_event_cb_t cb, void *user)
{
    s_cb = cb;
    s_cb_user = user;
}

int wifix_list_count(void) { return prov_storage_count(); }

esp_err_t wifix_list_get(int index, char *ssid_out, size_t cap)
{
    int max_n = s_rt.max_networks;
    prov_creds_t *list = calloc(max_n, sizeof(prov_creds_t));
    if (!list) return ESP_ERR_NO_MEM;
    int n = 0;
    prov_storage_load_all(list, max_n, &n);
    esp_err_t err = ESP_ERR_NOT_FOUND;
    if (index >= 0 && index < n) {
        strlcpy(ssid_out, list[index].ssid, cap);
        err = ESP_OK;
    }
    free(list);
    return err;
}

void wifix_request_provisioning_on_next_boot(void)
{
    prov_storage_set_force_flag();
}

// ---- 默认值整合 ----
static int pick_int(int v, int kc) { return v > 0 ? v : kc; }

static void load_runtime(const wifix_config_t *cfg)
{
    const char *prefix = (cfg && cfg->ap_ssid_prefix) ? cfg->ap_ssid_prefix
                                                       : CONFIG_WIFIX_AP_SSID_PREFIX;
    strlcpy(s_rt.ap_ssid_prefix, prefix, sizeof(s_rt.ap_ssid_prefix));

    s_rt.max_networks            = pick_int(cfg ? cfg->max_networks : 0,
                                            CONFIG_WIFIX_MAX_NETWORKS);
    s_rt.http_port               = pick_int(cfg ? cfg->http_port : 0,
                                            CONFIG_WIFIX_HTTP_PORT);
    // power_cycle_threshold：>0 用 cfg；<0 关闭功能；==0 用 Kconfig
    if (cfg && cfg->power_cycle_threshold > 0) {
        s_rt.power_cycle_threshold = cfg->power_cycle_threshold;
    } else if (cfg && cfg->power_cycle_threshold < 0) {
        s_rt.power_cycle_threshold = 0;
    } else {
        s_rt.power_cycle_threshold = CONFIG_WIFIX_POWER_CYCLE_THRESHOLD;
    }
    s_rt.power_cycle_stable_ms   = CONFIG_WIFIX_POWER_CYCLE_STABLE_MS;
    s_rt.sta_connect_timeout_ms  = pick_int(cfg ? cfg->sta_connect_timeout_ms : 0,
                                            CONFIG_WIFIX_STA_CONNECT_TIMEOUT_MS);
    s_rt.sta_retry_round_delay_ms = pick_int(cfg ? cfg->sta_retry_round_delay_ms : 0,
                                              CONFIG_WIFIX_STA_RETRY_ROUND_DELAY_MS);

    if (cfg && cfg->enable_sta_http > 0) {
        s_rt.enable_sta_http = true;
    } else if (cfg && cfg->enable_sta_http < 0) {
        s_rt.enable_sta_http = false;  // 显式 -1 关闭
    } else {
        s_rt.enable_sta_http = true;   // 0 或未设：默认开
    }

#ifdef CONFIG_WIFIX_REQUIRE_AUTH_IN_AP
    s_rt.require_auth_in_ap = true;
#else
    s_rt.require_auth_in_ap = false;
#endif
}

static void start_sta_http(void)
{
    if (!s_rt.enable_sta_http) return;
    httpd_config_t hcfg = HTTPD_DEFAULT_CONFIG();
    hcfg.server_port = s_rt.http_port;
    hcfg.lru_purge_enable = true;
    hcfg.max_uri_handlers = 16;
    if (httpd_start(&s_sta_httpd, &hcfg) != ESP_OK) {
        ESP_LOGE(TAG, "STA httpd_start 失败");
        return;
    }
    prov_http_register(s_sta_httpd, false);
    ESP_LOGI(TAG, "STA 管理界面已启动 (端口 %d)", s_rt.http_port);
}

// 等首次 CONNECTED，启 STA HTTP 后任务自删，不再轮询
static void sta_state_watcher(void *arg)
{
    while (wifix_state() != WIFIX_STATE_CONNECTED) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    start_sta_http();
    vTaskDelete(NULL);
}

esp_err_t wifix_start(const wifix_config_t *cfg)
{
    static bool s_started = false;
    if (s_started) {
        ESP_LOGW(TAG, "wifix_start 已调用过，忽略重入");
        return ESP_ERR_INVALID_STATE;
    }
    s_started = true;

    load_runtime(cfg);

    const char *def_user = (cfg && cfg->default_admin_user) ? cfg->default_admin_user
                                                              : CONFIG_WIFIX_DEFAULT_USERNAME;
    const char *def_pass = (cfg && cfg->default_admin_password) ? cfg->default_admin_password
                                                                  : CONFIG_WIFIX_DEFAULT_PASSWORD;

    ESP_LOGI(TAG, "启动 (max_networks=%d, http_port=%d, ap_prefix=%s)",
             s_rt.max_networks, s_rt.http_port, s_rt.ap_ssid_prefix);

    prov_storage_init(def_user, def_pass);

    bool triggered = prov_storage_power_cycle_check(s_rt.power_cycle_threshold,
                                                    s_rt.power_cycle_stable_ms);
    if (triggered) {
        // 计数到了：下次启动进配网。这次先正常走（避免无限循环）。
        // 但 force flag 已置位，下次开机生效——
        // 用户拔电再插一次（不构成连续）会进入配网模式。
    }

    bool force = prov_storage_consume_force_flag();
    int  count = prov_storage_count();

    if (force || count == 0) {
        ESP_LOGI(TAG, "进入 SoftAP 配网模式 (force=%d count=%d)", force, count);
        wifix_set_state(WIFIX_STATE_PROVISIONING);
        prov_softap_run();
        // 配网模式下 HTTP /done handler 会触发重启，这里阻塞挂着
        while (1) vTaskDelay(pdMS_TO_TICKS(1000));
    }

    ESP_LOGI(TAG, "进入 STA 模式 (saved=%d)", count);
    wifix_set_state(WIFIX_STATE_CONNECTING);
    prov_sta_start();

    if (s_rt.enable_sta_http) {
        xTaskCreate(sta_state_watcher, "wifix_w", 2048, NULL, 4, NULL);
    }

    return ESP_OK;
}
