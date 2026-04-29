// wifix - ESP32 WiFi 配网与多网络管理库
//
// 单一入口 wifix_start(&cfg)：
//   - power-cycle 检查（三连断电只设 force flag，不删凭证）
//   - 从 NVS 读多 WiFi 列表
//   - 列表为空或 force=1：进 SoftAP 配网模式
//   - 列表非空：进 STA，候选轮转直到连上
//   - STA 连上后（如启用）启 HTTP 管理界面
//
// 调用前必须先：
//   nvs_flash_init()       // 或加密版（见 README）
//   esp_netif_init()
//   esp_event_loop_create_default()
//
// 之后阻塞返回 ESP_OK 时 STA 已连上（CONNECTING/CONNECTED）；
// 配网模式则会重启自身切到 STA，函数不会返回。

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WIFIX_SSID_MAX 33
#define WIFIX_PASS_MAX 65
#define WIFIX_USER_MAX 33

typedef enum {
    WIFIX_STATE_BOOTING = 0,
    WIFIX_STATE_PROVISIONING,   // SoftAP 配网中
    WIFIX_STATE_CONNECTING,     // STA 候选尝试中
    WIFIX_STATE_CONNECTED,      // STA 已连上
    WIFIX_STATE_RETRYING,       // 全部候选失败，等下一轮重扫
} wifix_state_t;

typedef struct {
    // SoftAP SSID 前缀；NULL 表示用 Kconfig 默认（"Wifix-"）。
    // 实际 AP SSID = <前缀><MAC 后两字节十六进制>，如 "DriftCam-9075"。
    const char *ap_ssid_prefix;

    // 管理界面默认账号；NULL 表示用 Kconfig 默认（"admin"/"admin"）。
    // 仅在 NVS 还没存账密时写入；后续以 NVS 为准。
    const char *default_admin_user;
    const char *default_admin_password;

    // <=0 表示用 Kconfig 默认。
    int max_networks;
    int http_port;
    int power_cycle_threshold;
    int sta_connect_timeout_ms;
    int sta_retry_round_delay_ms;

    // STA 模式是否启 HTTP 管理界面：0=默认（开），1=强制开，-1=关闭
    int enable_sta_http;

    // STA TX 功率上限（单位 0.25 dBm；0 = 不动用 IDF 默认 80=20dBm）
    // ESP32-C3 SuperMini 焊飞线天线必设 52（13 dBm）防 RF 自激。
    // C6/S3/原装 C3 板载 PCB 天线无需设。
    int sta_max_tx_power_qdbm;
} wifix_config_t;

// 全 0 即可，所有字段会回退到 Kconfig 默认
#define WIFIX_DEFAULT_CONFIG() ((wifix_config_t){0})

typedef void (*wifix_event_cb_t)(wifix_state_t state, void *user);

// 主入口：阻塞至首次状态确定（CONNECTING 或 PROVISIONING 进入）
esp_err_t wifix_start(const wifix_config_t *cfg);

// 状态查询
wifix_state_t wifix_state(void);
int           wifix_rssi(void);
const char   *wifix_current_ssid(void);  // 未连返回 NULL

// 当前 STA 模式 DHCP 获得的 IP；写入 out（至少 16 字节）
// 未连接返回 ESP_ERR_INVALID_STATE，out[0]=0
esp_err_t     wifix_current_ip(char *out, size_t cap);

// 注册状态变化回调（线程安全；同步从内部任务调用，回调里别阻塞）
void wifix_set_event_cb(wifix_event_cb_t cb, void *user);

// 进阶：业务代码也想列已存网络
int       wifix_list_count(void);
esp_err_t wifix_list_get(int index, char *ssid_out, size_t cap);

// 主动触发"下次启动进配网"（重启后生效；不删凭证）
void wifix_request_provisioning_on_next_boot(void);

#ifdef __cplusplus
}
#endif
