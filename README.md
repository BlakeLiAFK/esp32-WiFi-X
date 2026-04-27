# wifix

ESP32 WiFi 配网与多网络管理 component。

适用 ESP32 / C3 / C6 / S3，ESP-IDF v5.3+。

## 特性

- SoftAP + Captive Portal：手机连上自动弹配网页（DNS 劫持 + DHCP option 6 已正确处理）
- 多 WiFi 凭证（默认上限 16 条），按 RSSI 自动选择信号最强可用网络
- 全程 Web 管理：SoftAP 模式配网，STA 模式同样可访问设备 IP 增删 WiFi
- HTTP Basic Auth：STA 模式强制鉴权，账号 NVS 存储可改
- 三连断电进配网：仅设 flag，**不删除已存凭证**
- 单一对外头文件 `wifix.h`，单一入口 `wifix_start(&cfg)`
- 不占用任何 GPIO（无 BOOT 按键依赖）

## 快速开始

### 1. 把 component 加入项目

项目根 `CMakeLists.txt`：
```cmake
cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS $ENV{HOME}/esp/components)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(myapp)
```

### 2. 业务代码

`main/app_main.c`：
```c
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "wifix.h"

void app_main(void) {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();

    wifix_config_t cfg = WIFIX_DEFAULT_CONFIG();
    cfg.ap_ssid_prefix = "MyDevice-";
    wifix_start(&cfg);

    // 业务逻辑：等 wifix_state() == WIFIX_STATE_CONNECTED 后开干
}
```

`main/CMakeLists.txt`：
```cmake
idf_component_register(SRCS "app_main.c" INCLUDE_DIRS ".")
```

### 3. menuconfig 调参

`idf.py menuconfig` → `Wifix - WiFi Provisioning`：
- `WIFIX_MAX_NETWORKS` 默认 16
- `WIFIX_DEFAULT_USERNAME` / `WIFIX_DEFAULT_PASSWORD` 默认 `admin` / `admin`
- `WIFIX_AP_SSID_PREFIX` 默认 `Wifix-`
- `WIFIX_HTTP_PORT` 默认 80
- `WIFIX_POWER_CYCLE_THRESHOLD` 默认 3
- `WIFIX_REQUIRE_AUTH_IN_AP` 默认 n（SoftAP 免认证）

`cfg` 字段优先于 Kconfig；都没设则用代码内置默认。

## 工作流

```
boot
 ├─ power-cycle 计数 +1，3s 后清零
 │  └─ 若计数 >= 3 → set force_prov=1（不删凭证），下次启动进配网
 ├─ 读 force_prov flag（读后清零）
 ├─ 读 NVS 凭证列表
 │
 ├─ force=1 或 列表为空 ─→ SoftAP 配网模式
 │                          ├─ 预扫描周边 AP 缓存
 │                          ├─ 启 AP "<prefix><MAC4-5>"
 │                          ├─ DHCP 下发 DNS=192.168.4.1（关键！）
 │                          ├─ DNS 劫持所有 A 记录
 │                          ├─ HTTP server + 配网页
 │                          └─ /done 后 esp_restart 切 STA
 │
 └─ 否则 ─→ STA 模式
            ├─ 扫描 → 与已存列表求交 → RSSI 排序
            ├─ 依次 connect，单条 10s 超时
            ├─ 全失败等 30s 重扫
            ├─ 断线先重试同条，失败再回大循环
            └─ 连上后启 HTTP 管理界面（同样的网页）
```

## API

```c
esp_err_t      wifix_start(const wifix_config_t *cfg);
wifix_state_t  wifix_state(void);
int            wifix_rssi(void);
const char    *wifix_current_ssid(void);
int            wifix_list_count(void);
esp_err_t      wifix_list_get(int idx, char *out, size_t cap);

void           wifix_set_event_cb(wifix_event_cb_t cb, void *user);
void           wifix_request_provisioning_on_next_boot(void);
```

## NVS 加密接入

库本身**不接管** NVS init，让调用方按 ESP-IDF 标准做加密 init。最简方案（HMAC eFuse Scheme）：

### 1. partitions.csv 加 nvs_keys 分区
```
nvs,      data, nvs,     0x9000, 0x6000
nvs_keys, data, nvs_keys,,       0x1000, encrypted
```

### 2. sdkconfig
```
CONFIG_NVS_ENCRYPTION=y
CONFIG_NVS_SEC_PROVIDER_HMAC_EFUSE=y
CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC=y
CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID_FOR_ENCR_0=0
```

### 3. app_main 里在 nvs_flash_init 之前
```c
#include "nvs_sec_provider.h"
#include "nvs_flash.h"

static esp_err_t nvs_init_encrypted(void) {
    nvs_sec_cfg_t cfg;
    nvs_sec_scheme_t *scheme = NULL;
    nvs_sec_config_hmac_t hmac_cfg = NVS_SEC_PROVIDER_CFG_HMAC_DEFAULT();
    ESP_ERROR_CHECK(nvs_sec_provider_register_hmac(&hmac_cfg, &scheme));

    esp_err_t err = nvs_flash_read_security_cfg_v2(scheme, &cfg);
    if (err == ESP_ERR_NVS_KEYS_NOT_INITIALIZED) {
        err = nvs_flash_generate_keys_v2(scheme, &cfg);
    }
    if (err != ESP_OK) return err;
    return nvs_flash_secure_init(&cfg);
}
```

### 4. 工厂阶段把 HMAC key 烧入 eFuse
```bash
espefuse.py --port /dev/cu.usbmodemXXX burn_key BLOCK_KEY0 \
    hmac_key.bin HMAC_UP
```

完整示例见 `examples/encrypted/`。

## 已知约束

- Captive portal 行为依赖手机系统：iOS/macOS 探测 captive.apple.com，Android 探测 connectivitycheck.gstatic.com。库已正确响应这些探测。
- ESP-IDF `wifi_config_t` 一次只能装一个 AP，多 SSID 必须自行扫描+候选轮转（库已实现）。
- SoftAP 模式 `/scan` 用启动时缓存，避免实时扫描掐断已连客户端。

## License

MIT
