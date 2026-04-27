// 迷你 DNS 服务器：所有 A 记录回 hijack_ip
// 配合 SoftAP DHCP option 6 把 captive portal 探测引到设备本身

#include "prov_internal.h"

#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

static const char *TAG = "wifix.dns";

typedef struct {
    uint16_t id, flags, qd, an, ns, ar;
} __attribute__((packed)) dns_hdr_t;

static volatile uint32_t s_hijack_ip;
static TaskHandle_t s_task;
static int s_sock = -1;
static volatile bool s_run;
static SemaphoreHandle_t s_done;

static void dns_task(void *arg)
{
    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s_sock < 0) {
        ESP_LOGE(TAG, "socket 失败");
        goto out;
    }
    // 1s 超时让循环周期性检查 s_run，避免依赖 shutdown 唤醒
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in a = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(53),
    };
    if (bind(s_sock, (struct sockaddr *)&a, sizeof(a)) < 0) {
        ESP_LOGE(TAG, "bind :53 失败");
        goto out;
    }

    uint8_t buf[512];
    while (s_run) {
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        int n = recvfrom(s_sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
        if (n < 0) continue;  // 超时或错误，回到 while 检查 s_run
        if (n < (int)sizeof(dns_hdr_t)) continue;

        dns_hdr_t *h = (dns_hdr_t *)buf;
        if (ntohs(h->qd) < 1) continue;

        uint8_t *p = buf + sizeof(dns_hdr_t);
        uint8_t *end = buf + n;
        // 跳过 QNAME（length-prefixed labels 至 0），含越界校验
        bool ok = false;
        while (p < end) {
            uint8_t lbl = *p;
            if (lbl == 0) { p++; ok = true; break; }
            if (lbl & 0xC0) break;             // 不支持指针压缩
            if (p + 1 + lbl >= end) break;     // 防 label 跨越 end
            p += 1 + lbl;
        }
        if (!ok) continue;
        if (p + 4 > end) continue;
        uint16_t qtype = ((uint16_t)p[0] << 8) | p[1];
        p += 4;

        h->flags = htons(0x8180);
        h->an = htons(qtype == 1 ? 1 : 0);
        h->ns = h->ar = 0;

        if (qtype == 1) {
            // 检查写入空间：name pointer(2)+type(2)+class(2)+TTL(4)+rdlen(2)+ip(4) = 16
            if (p + 16 > buf + sizeof(buf)) continue;
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

out:
    if (s_sock >= 0) {
        close(s_sock);
        s_sock = -1;
    }
    s_task = NULL;
    if (s_done) xSemaphoreGive(s_done);
    vTaskDelete(NULL);
}

void dns_hijack_start(uint32_t hijack_ip_be)
{
    if (s_task) {
        ESP_LOGW(TAG, "已在运行，忽略 start");
        return;
    }
    if (!s_done) s_done = xSemaphoreCreateBinary();
    s_hijack_ip = hijack_ip_be;
    s_run = true;
    if (xTaskCreate(dns_task, "wifix_dns", 4096, NULL, 5, &s_task) != pdPASS) {
        ESP_LOGE(TAG, "task 创建失败");
        s_run = false;
        return;
    }
    ESP_LOGI(TAG, "DNS 劫持启动");
}

void dns_hijack_stop(void)
{
    if (!s_task) return;
    s_run = false;
    // 等任务自然退出（最多 1.5s 覆盖 RCVTIMEO 超时一次）
    if (s_done) xSemaphoreTake(s_done, pdMS_TO_TICKS(1500));
    ESP_LOGI(TAG, "DNS 劫持已停");
}
