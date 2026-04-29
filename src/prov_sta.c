// 多 WiFi STA 自动选择
//
// 核心逻辑：
//   1. 扫一轮，把扫到的 AP 与 NVS 已存条目求交集，按 RSSI 降序排成候选队列
//   2. 依次 connect，单条超时 sta_connect_timeout_ms
//   3. 拿到 IP → 进入 CONNECTED；任一 disconnect 事件先重试同条 3 次，再回到 1
//   4. 候选队列空 → 等 sta_retry_round_delay_ms 重扫

#include "prov_internal.h"

#include <string.h>
#include <stdlib.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

static const char *TAG = "wifix.sta";

#define EVT_GOT_IP        BIT0
#define EVT_DISCONNECTED  BIT1
#define EVT_KICK          BIT2

static EventGroupHandle_t s_evt;
static TaskHandle_t s_task;
static volatile bool s_connected;
static char s_current_ssid[WIFIX_SSID_MAX] = {0};
static int  s_current_rssi = 0;

typedef struct {
    char ssid[WIFIX_SSID_MAX];
    int  rssi;
} cand_t;

static int cand_cmp(const void *a, const void *b)
{
    return ((const cand_t *)b)->rssi - ((const cand_t *)a)->rssi;
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        s_current_rssi = 0;
        if (s_evt) xEventGroupSetBits(s_evt, EVT_DISCONNECTED);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "已连接 SSID=%s IP=" IPSTR, s_current_ssid, IP2STR(&e->ip_info.ip));
        s_connected = true;
        if (s_evt) xEventGroupSetBits(s_evt, EVT_GOT_IP);
    }
}

// 扫描 + 与 NVS 列表求交集，按 RSSI 降序写入 cands；返回数量
static int build_candidates(cand_t *cands, int cap)
{
    wifi_scan_config_t cfg = {
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active = {.min = 80, .max = 150},
    };
    if (esp_wifi_scan_start(&cfg, true) != ESP_OK) {
        ESP_LOGW(TAG, "扫描失败");
        return 0;
    }
    uint16_t scan_n = 0;
    esp_wifi_scan_get_ap_num(&scan_n);
    if (scan_n == 0) return 0;

    wifi_ap_record_t *recs = malloc(sizeof(wifi_ap_record_t) * scan_n);
    if (!recs) return 0;
    esp_wifi_scan_get_ap_records(&scan_n, recs);

    int max_n = prov_rt()->max_networks;
    prov_creds_t *saved = calloc(max_n, sizeof(prov_creds_t));
    if (!saved) { free(recs); return 0; }
    int saved_n = 0;
    prov_storage_load_all(saved, max_n, &saved_n);

    int cn = 0;
    for (int i = 0; i < (int)scan_n && cn < cap; i++) {
        const char *s = (const char *)recs[i].ssid;
        if (!s[0]) continue;
        for (int j = 0; j < saved_n; j++) {
            if (strcmp(saved[j].ssid, s) == 0) {
                // 去重：扫描结果可能同 SSID 多个 BSSID
                bool dup = false;
                for (int k = 0; k < cn; k++) {
                    if (strcmp(cands[k].ssid, s) == 0) { dup = true; break; }
                }
                if (!dup) {
                    strlcpy(cands[cn].ssid, s, sizeof(cands[cn].ssid));
                    cands[cn].rssi = recs[i].rssi;
                    cn++;
                }
                break;
            }
        }
    }
    free(saved);
    free(recs);

    qsort(cands, cn, sizeof(cand_t), cand_cmp);
    return cn;
}

// 用 ssid+pass 试一次连接，等超时；成功返回 true
static bool try_connect(const char *ssid, const char *pass, int timeout_ms)
{
    bool has_pass = pass && pass[0];

    wifi_config_t wcfg = {0};
    strlcpy((char *)wcfg.sta.ssid, ssid, sizeof(wcfg.sta.ssid));
    strlcpy((char *)wcfg.sta.password, has_pass ? pass : "", sizeof(wcfg.sta.password));
    // 默认要求 WPA-PSK 及以上；空密码降级为开放，避免被同名钓鱼开放 AP 抢连
    wcfg.sta.threshold.authmode = has_pass ? WIFI_AUTH_WPA_PSK : WIFI_AUTH_OPEN;
    wcfg.sta.pmf_cfg.capable = true;
    wcfg.sta.scan_method = WIFI_FAST_SCAN;
    wcfg.sta.threshold.rssi = -90;

    esp_wifi_set_config(WIFI_IF_STA, &wcfg);

    strlcpy(s_current_ssid, ssid, sizeof(s_current_ssid));

    // 先吃掉一个 disconnect 事件（如果当前已连，esp_wifi_disconnect 会异步触发）
    // 否则该事件会在新 connect 还没结果时被误识为本次失败
    esp_wifi_disconnect();
    xEventGroupWaitBits(s_evt, EVT_DISCONNECTED, pdTRUE, pdFALSE, pdMS_TO_TICKS(500));
    xEventGroupClearBits(s_evt, EVT_GOT_IP | EVT_DISCONNECTED | EVT_KICK);

    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "wifi_connect 立即失败 (%s) err=0x%x", ssid, err);
        return false;
    }

    EventBits_t bits = xEventGroupWaitBits(
        s_evt, EVT_GOT_IP | EVT_DISCONNECTED | EVT_KICK,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(timeout_ms));

    if (bits & EVT_GOT_IP) return true;
    return false;
}

static void sta_task(void *arg)
{
    int max_n = prov_rt()->max_networks;
    cand_t *cands = calloc(max_n, sizeof(cand_t));
    if (!cands) {
        ESP_LOGE(TAG, "OOM");
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        wifix_set_state(WIFIX_STATE_CONNECTING);
        ESP_LOGI(TAG, "开始候选扫描");
        int cn = build_candidates(cands, max_n);
        ESP_LOGI(TAG, "扫描完成，匹配候选 %d 条", cn);

        bool got_one = false;
        for (int i = 0; i < cn; i++) {
            char pass[WIFIX_PASS_MAX] = {0};
            prov_storage_get_pass(cands[i].ssid, pass, sizeof(pass));
            ESP_LOGI(TAG, "尝试 [%d/%d] ssid=\"%s\" (len=%d) pass_len=%d RSSI=%d",
                     i + 1, cn, cands[i].ssid,
                     (int)strlen(cands[i].ssid), (int)strlen(pass), cands[i].rssi);
            if (try_connect(cands[i].ssid, pass, prov_rt()->sta_connect_timeout_ms)) {
                wifix_set_state(WIFIX_STATE_CONNECTED);
                got_one = true;
                // 阻塞直到断线或外部 kick
                EventBits_t bits = xEventGroupWaitBits(
                    s_evt, EVT_DISCONNECTED | EVT_KICK,
                    pdTRUE, pdFALSE, portMAX_DELAY);
                ESP_LOGW(TAG, "STA 状态变化 bits=0x%x", (unsigned)bits);
                wifix_set_state(WIFIX_STATE_CONNECTING);
                // 同条快速重试一次再回大循环
                if (try_connect(cands[i].ssid, pass, prov_rt()->sta_connect_timeout_ms)) {
                    wifix_set_state(WIFIX_STATE_CONNECTED);
                    xEventGroupWaitBits(s_evt, EVT_DISCONNECTED | EVT_KICK,
                                         pdTRUE, pdFALSE, portMAX_DELAY);
                    wifix_set_state(WIFIX_STATE_CONNECTING);
                }
                break;
            }
            ESP_LOGW(TAG, "[%s] 连接失败", cands[i].ssid);
        }

        if (got_one) continue;  // 重新扫描

        // 全失败：进 RETRYING 等一会儿
        wifix_set_state(WIFIX_STATE_RETRYING);
        ESP_LOGW(TAG, "全部候选失败，%d ms 后重扫", prov_rt()->sta_retry_round_delay_ms);
        EventBits_t kicked = xEventGroupWaitBits(
            s_evt, EVT_KICK, pdTRUE, pdFALSE,
            pdMS_TO_TICKS(prov_rt()->sta_retry_round_delay_ms));
        (void)kicked;
    }
}

esp_err_t prov_sta_start(void)
{
    s_evt = xEventGroupCreate();
    s_connected = false;

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT,   IP_EVENT_STA_GOT_IP, on_event, NULL, NULL);

    esp_wifi_set_mode(WIFI_MODE_STA);
    // 只用 b/g/n，规避部分 WiFi 6 路由的 OFDMA/HE 兼容问题
    esp_wifi_set_protocol(WIFI_IF_STA,
        WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_wifi_start();

    // 必须在 esp_wifi_start 之后设置；C3 SuperMini 飞线天线必降到 13dBm 防自激
    if (prov_rt()->sta_max_tx_power_qdbm > 0) {
        esp_wifi_set_max_tx_power((int8_t)prov_rt()->sta_max_tx_power_qdbm);
        int8_t cur = 0;
        esp_wifi_get_max_tx_power(&cur);
        ESP_LOGI(TAG, "TX power 设为 %d * 0.25dBm = %.1f dBm", cur, cur * 0.25f);
    }

    xTaskCreate(sta_task, "wifix_sta", 4096, NULL, 5, &s_task);
    return ESP_OK;
}

bool prov_sta_is_connected(void) { return s_connected; }

int prov_sta_rssi(void)
{
    if (!s_connected) return 0;
    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        s_current_rssi = ap.rssi;
        return ap.rssi;
    }
    return s_current_rssi;
}

const char *prov_sta_current_ssid(void)
{
    return s_connected ? s_current_ssid : NULL;
}

void prov_sta_kick_rescan(void)
{
    if (s_evt) xEventGroupSetBits(s_evt, EVT_KICK);
}
