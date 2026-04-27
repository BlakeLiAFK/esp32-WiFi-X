// SoftAP 配网模式
//   1. 用 STA-only 模式做一次预扫描，缓存到 prov_http
//   2. 切到 AP-only 启 SoftAP
//   3. 设 DHCP option 6 把 DNS 推给客户端（关键）
//   4. 启 HTTP server + DNS 劫持
//   5. 阻塞等待外部触发重启

#include "prov_internal.h"

#include <string.h>
#include <stdio.h>

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "wifix.ap";

#define PRESCAN_MAX 12

static void make_ap_ssid(char *out, size_t cap)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(out, cap, "%s%02X%02X", prov_rt()->ap_ssid_prefix, mac[4], mac[5]);
}

static void prescan(void)
{
    wifi_scan_config_t cfg = {
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active = {.min = 80, .max = 150},
    };
    if (esp_wifi_scan_start(&cfg, true) != ESP_OK) {
        ESP_LOGW(TAG, "预扫描失败");
        prov_set_scan_cache(NULL, 0);
        return;
    }
    uint16_t n = 0;
    esp_wifi_scan_get_ap_num(&n);
    if (n > PRESCAN_MAX) n = PRESCAN_MAX;
    if (n == 0) {
        prov_set_scan_cache(NULL, 0);
        return;
    }
    wifi_ap_record_t recs[PRESCAN_MAX];
    esp_wifi_scan_get_ap_records(&n, recs);

    prov_scan_entry_t entries[PRESCAN_MAX];
    for (int i = 0; i < n; i++) {
        strlcpy(entries[i].ssid, (const char *)recs[i].ssid, sizeof(entries[i].ssid));
        entries[i].rssi = recs[i].rssi;
        entries[i].authmode = recs[i].authmode;
    }
    prov_set_scan_cache(entries, n);
    ESP_LOGI(TAG, "预扫描 %d 个 AP", n);
}

void prov_softap_run(void)
{
    char ap_ssid[32];
    make_ap_ssid(ap_ssid, sizeof(ap_ssid));
    ESP_LOGI(TAG, "进入配网模式 AP=%s", ap_ssid);

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&init);

    // 阶段 1：纯 STA 预扫描
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    prescan();
    esp_wifi_stop();

    // 阶段 2：切 AP
    wifi_config_t wcfg = {0};
    strlcpy((char *)wcfg.ap.ssid, ap_ssid, sizeof(wcfg.ap.ssid));
    wcfg.ap.ssid_len = strlen(ap_ssid);
    wcfg.ap.channel = 6;
    wcfg.ap.max_connection = 3;
    wcfg.ap.authmode = WIFI_AUTH_OPEN;

    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &wcfg);
    esp_wifi_start();

    // DHCP option 6 (DNS) → 192.168.4.1，关键修复
    {
        esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (ap_netif) {
            esp_netif_dhcps_stop(ap_netif);
            esp_netif_dns_info_t dns = {0};
            dns.ip.u_addr.ip4.addr = ESP_IP4TOADDR(192, 168, 4, 1);
            dns.ip.type = ESP_IPADDR_TYPE_V4;
            esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns);
            uint8_t enable = 1;
            esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET,
                                    ESP_NETIF_DOMAIN_NAME_SERVER,
                                    &enable, sizeof(enable));
            esp_netif_dhcps_start(ap_netif);
            ESP_LOGI(TAG, "DHCP option 6 (DNS=192.168.4.1) 已启用");
        }
    }

    // HTTP server
    httpd_handle_t srv = NULL;
    httpd_config_t hcfg = HTTPD_DEFAULT_CONFIG();
    hcfg.server_port = prov_rt()->http_port;
    hcfg.lru_purge_enable = true;
    hcfg.max_uri_handlers = 16;
    if (httpd_start(&srv, &hcfg) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start 失败");
        return;
    }
    prov_http_register(srv, true);

    // DNS 劫持：192.168.4.1 网络字节序
    dns_hijack_start(0x0104A8C0);

    ESP_LOGI(TAG, "配网网页 http://192.168.4.1");
}
