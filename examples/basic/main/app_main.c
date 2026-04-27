// wifix 基础使用示例
//
// 烧录后：
//   - 首次启动会启 SoftAP "Wifix-XXXX"，手机连上自动弹配网页
//   - 配置一个 WiFi 后会重启进 STA 模式
//   - 之后浏览器访问 http://<设备 IP>/ 可继续增删 WiFi
//   - 默认账号：admin / admin

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "wifix.h"

static const char *TAG = "app";

static void on_state(wifix_state_t st, void *user)
{
    const char *names[] = {"BOOTING", "PROVISIONING", "CONNECTING", "CONNECTED", "RETRYING"};
    ESP_LOGI(TAG, "state -> %s", names[st]);
}

void app_main(void)
{
    // NVS / netif / event loop 初始化
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifix_set_event_cb(on_state, NULL);

    wifix_config_t cfg = WIFIX_DEFAULT_CONFIG();
    cfg.ap_ssid_prefix = "Wifix-";
    ESP_ERROR_CHECK(wifix_start(&cfg));

    // 业务逻辑：等连上后做事
    while (1) {
        if (wifix_state() == WIFIX_STATE_CONNECTED) {
            ESP_LOGI(TAG, "已连接 SSID=%s RSSI=%d",
                     wifix_current_ssid(), wifix_rssi());
        }
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
