// 内部头：模块间共享，不暴露给调用方
#pragma once

#include <stdbool.h>
#include "esp_err.h"
#include "esp_http_server.h"
#include "wifix.h"

#define PROV_NVS_NAMESPACE "wifix"

// ---- 全局运行时配置（启动时由 wifix_start 填充） ----
typedef struct {
    char  ap_ssid_prefix[16];
    int   max_networks;
    int   http_port;
    int   power_cycle_threshold;
    int   power_cycle_stable_ms;
    int   sta_connect_timeout_ms;
    int   sta_retry_round_delay_ms;
    bool  enable_sta_http;
    bool  require_auth_in_ap;
    int   sta_max_tx_power_qdbm;
} prov_runtime_t;

const prov_runtime_t *prov_rt(void);

void wifix_set_state(wifix_state_t st);

// ---- prov_storage ----
typedef struct {
    char ssid[WIFIX_SSID_MAX];
    char pass[WIFIX_PASS_MAX];
} prov_creds_t;

esp_err_t prov_storage_init(const char *default_user, const char *default_pass);
int       prov_storage_count(void);
esp_err_t prov_storage_load_all(prov_creds_t *out, int cap, int *n);
esp_err_t prov_storage_get_pass(const char *ssid, char *pass_out, size_t cap);
esp_err_t prov_storage_add(const char *ssid, const char *pass);   // 同名覆盖
esp_err_t prov_storage_remove(const char *ssid);
esp_err_t prov_storage_clear_all(void);

bool      prov_storage_check_credentials(const char *user, const char *pass);
esp_err_t prov_storage_set_credentials(const char *user, const char *pass);
esp_err_t prov_storage_get_username(char *out, size_t cap);

bool      prov_storage_consume_force_flag(void);
void      prov_storage_set_force_flag(void);
bool      prov_storage_power_cycle_check(int threshold, int stable_ms);

// ---- prov_softap ----
// 阻塞直到收到 /done 或重启；返回时调用方应自行决定是否 esp_restart
void prov_softap_run(void);

// ---- prov_sta ----
esp_err_t prov_sta_start(void);
bool      prov_sta_is_connected(void);
int       prov_sta_rssi(void);
const char *prov_sta_current_ssid(void);
// 让候选队列重选（外部新增/删除凭证后调）
void      prov_sta_kick_rescan(void);

// ---- prov_http ----
// 在 srv 上注册所有管理路由；softap=true 时不要求 Basic Auth（除非 Kconfig 开启）
void prov_http_register(httpd_handle_t srv, bool softap);

// SoftAP 预扫描结果给 prov_http 用（仅 SoftAP 模式下有数据）
typedef struct {
    char  ssid[WIFIX_SSID_MAX];
    int   rssi;
    int   authmode;
} prov_scan_entry_t;
void prov_set_scan_cache(const prov_scan_entry_t *list, int n);
int  prov_get_scan_cache(prov_scan_entry_t *out, int cap);

// ---- prov_auth ----
// 校验 Authorization: Basic 头；softap=true 时按 Kconfig 决定是否跳过
bool prov_auth_check(httpd_req_t *req, bool softap);
void prov_auth_send_401(httpd_req_t *req);

// ---- dns_hijack ----
void dns_hijack_start(uint32_t hijack_ip_be);  // 网络字节序
void dns_hijack_stop(void);
