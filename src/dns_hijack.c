// 迷你 DNS 服务器：所有 A 记录回 hijack_ip
// 配合 SoftAP DHCP option 6 把 captive portal 探测引到设备本身

#include "prov_internal.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "wifix.dns";

typedef struct {
    uint16_t id, flags, qd, an, ns, ar;
} __attribute__((packed)) dns_hdr_t;

static volatile uint32_t s_hijack_ip;
static TaskHandle_t s_task;
static int s_sock = -1;
static volatile bool s_run;

static void dns_task(void *arg)
{
    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s_sock < 0) {
        ESP_LOGE(TAG, "socket 失败");
        vTaskDelete(NULL);
        return;
    }
    struct sockaddr_in a = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(53),
    };
    if (bind(s_sock, (struct sockaddr *)&a, sizeof(a)) < 0) {
        ESP_LOGE(TAG, "bind :53 失败");
        close(s_sock);
        s_sock = -1;
        vTaskDelete(NULL);
        return;
    }

    uint8_t buf[512];
    while (s_run) {
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        int n = recvfrom(s_sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
        if (n < (int)sizeof(dns_hdr_t)) continue;

        dns_hdr_t *h = (dns_hdr_t *)buf;
        if (ntohs(h->qd) < 1) continue;

        uint8_t *p = buf + sizeof(dns_hdr_t);
        uint8_t *end = buf + n;
        while (p < end && *p != 0) {
            if (*p & 0xC0) { p = end; break; }
            p += (*p) + 1;
        }
        if (p >= end) continue;
        p++;
        if (p + 4 > end) continue;
        uint16_t qtype = ((uint16_t)p[0] << 8) | p[1];
        p += 4;

        h->flags = htons(0x8180);
        h->an = htons(qtype == 1 ? 1 : 0);
        h->ns = h->ar = 0;

        if (qtype == 1) {  // A
            *p++ = 0xC0; *p++ = 0x0C;
            *p++ = 0x00; *p++ = 0x01;
            *p++ = 0x00; *p++ = 0x01;
            *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 60;
            *p++ = 0x00; *p++ = 0x04;
            uint32_t ip = s_hijack_ip;
            memcpy(p, &ip, 4); p += 4;
        }
        sendto(s_sock, buf, p - buf, 0, (struct sockaddr *)&src, sl);
    }

    close(s_sock);
    s_sock = -1;
    vTaskDelete(NULL);
}

void dns_hijack_start(uint32_t hijack_ip_be)
{
    if (s_run) return;
    s_hijack_ip = hijack_ip_be;
    s_run = true;
    xTaskCreate(dns_task, "wifix_dns", 4096, NULL, 5, &s_task);
    ESP_LOGI(TAG, "DNS 劫持启动");
}

void dns_hijack_stop(void)
{
    s_run = false;
    if (s_sock >= 0) shutdown(s_sock, SHUT_RDWR);
}
