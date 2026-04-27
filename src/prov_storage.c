// 多 WiFi 凭证 + 管理账密 + power-cycle/force 标志位
//
// NVS 布局（namespace = "wifix"）：
//   list      blob       {u8 count, [ssid 33B, pass 65B] x count}（原子写）
//   au        str        管理界面用户名
//   ap        str        管理界面密码
//   force     u8         "下次启动进配网" flag
//   pwr       u8         power-cycle 短电启动计数
//
// 注意：list 用 blob 一次性 set+commit，保证 NVS 层原子；杜绝多键 rewrite 中途
// 掉电导致 count 与条目错位的问题。

#include "prov_internal.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "wifix.store";

#define KEY_LIST      "list"
#define KEY_USER      "au"
#define KEY_PASS      "ap"
#define KEY_FORCE     "force"
#define KEY_PWRCNT    "pwr"

#define ENTRY_SIZE    (WIFIX_SSID_MAX + WIFIX_PASS_MAX)

static int s_max_networks = 16;

static esp_err_t open_rw(nvs_handle_t *h)
{
    return nvs_open(PROV_NVS_NAMESPACE, NVS_READWRITE, h);
}

static esp_err_t open_ro(nvs_handle_t *h)
{
    return nvs_open(PROV_NVS_NAMESPACE, NVS_READONLY, h);
}

// 序列化：[u8 count][ssid_0 33B][pass_0 65B]...
static size_t blob_size(int n)
{
    return 1 + (size_t)n * ENTRY_SIZE;
}

static void blob_pack(uint8_t *buf, const prov_creds_t *list, int n)
{
    buf[0] = (uint8_t)n;
    uint8_t *p = buf + 1;
    for (int i = 0; i < n; i++) {
        memset(p, 0, ENTRY_SIZE);
        strlcpy((char *)p, list[i].ssid, WIFIX_SSID_MAX);
        strlcpy((char *)(p + WIFIX_SSID_MAX), list[i].pass, WIFIX_PASS_MAX);
        p += ENTRY_SIZE;
    }
}

static int blob_unpack(const uint8_t *buf, size_t buf_len, prov_creds_t *out, int cap)
{
    if (buf_len < 1) return 0;
    int n = buf[0];
    if (n > cap) n = cap;
    if (n > s_max_networks) n = s_max_networks;
    size_t need = blob_size(n);
    if (buf_len < need) return 0;
    const uint8_t *p = buf + 1;
    int outn = 0;
    for (int i = 0; i < n && outn < cap; i++) {
        const char *ssid = (const char *)p;
        const char *pass = (const char *)(p + WIFIX_SSID_MAX);
        if (ssid[0]) {
            strlcpy(out[outn].ssid, ssid, sizeof(out[outn].ssid));
            // pass 缓冲已包含 \0（pack 时 memset），strlcpy 直接拷
            strlcpy(out[outn].pass, pass, sizeof(out[outn].pass));
            outn++;
        }
        p += ENTRY_SIZE;
    }
    return outn;
}

static esp_err_t write_list(const prov_creds_t *list, int n)
{
    nvs_handle_t h;
    esp_err_t err = open_rw(&h);
    if (err != ESP_OK) return err;

    if (n == 0) {
        err = nvs_erase_key(h, KEY_LIST);
        if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    } else {
        size_t sz = blob_size(n);
        uint8_t *buf = calloc(1, sz);
        if (!buf) { nvs_close(h); return ESP_ERR_NO_MEM; }
        blob_pack(buf, list, n);
        err = nvs_set_blob(h, KEY_LIST, buf, sz);
        free(buf);
    }
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t prov_storage_init(const char *default_user, const char *default_pass)
{
    s_max_networks = prov_rt()->max_networks;

    nvs_handle_t h;
    esp_err_t err = open_rw(&h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open 失败 err=0x%x", err);
        return err;
    }

    size_t len = 0;
    if (nvs_get_str(h, KEY_USER, NULL, &len) == ESP_ERR_NVS_NOT_FOUND) {
        const char *u = default_user ? default_user : "admin";
        const char *p = default_pass ? default_pass : "admin";
        esp_err_t e1 = nvs_set_str(h, KEY_USER, u);
        esp_err_t e2 = nvs_set_str(h, KEY_PASS, p);
        esp_err_t e3 = nvs_commit(h);
        if (e1 || e2 || e3) {
            ESP_LOGE(TAG, "默认账密写入失败 e1=%x e2=%x e3=%x", e1, e2, e3);
            err = e1 ? e1 : (e2 ? e2 : e3);
        } else {
            ESP_LOGI(TAG, "首次启动，写入默认账密 %s/****", u);
        }
    }
    nvs_close(h);
    return err;
}

int prov_storage_count(void)
{
    nvs_handle_t h;
    if (open_ro(&h) != ESP_OK) return 0;
    size_t sz = 0;
    if (nvs_get_blob(h, KEY_LIST, NULL, &sz) != ESP_OK || sz < 1) {
        nvs_close(h);
        return 0;
    }
    uint8_t *buf = malloc(sz);
    if (!buf) { nvs_close(h); return 0; }
    int n = 0;
    if (nvs_get_blob(h, KEY_LIST, buf, &sz) == ESP_OK) {
        n = buf[0];
        if (n > s_max_networks) n = s_max_networks;
    }
    free(buf);
    nvs_close(h);
    return n;
}

esp_err_t prov_storage_load_all(prov_creds_t *out, int cap, int *count_out)
{
    if (count_out) *count_out = 0;

    nvs_handle_t h;
    esp_err_t err = open_ro(&h);
    if (err != ESP_OK) return err;

    size_t sz = 0;
    err = nvs_get_blob(h, KEY_LIST, NULL, &sz);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(h);
        return ESP_OK;  // 空列表
    }
    if (err != ESP_OK) { nvs_close(h); return err; }

    uint8_t *buf = malloc(sz);
    if (!buf) { nvs_close(h); return ESP_ERR_NO_MEM; }
    err = nvs_get_blob(h, KEY_LIST, buf, &sz);
    nvs_close(h);
    if (err != ESP_OK) { free(buf); return err; }

    int n = blob_unpack(buf, sz, out, cap);
    free(buf);
    if (count_out) *count_out = n;
    return ESP_OK;
}

esp_err_t prov_storage_get_pass(const char *ssid, char *pass_out, size_t cap)
{
    if (cap > 0) pass_out[0] = 0;
    prov_creds_t *list = calloc(s_max_networks, sizeof(prov_creds_t));
    if (!list) return ESP_ERR_NO_MEM;
    int n = 0;
    prov_storage_load_all(list, s_max_networks, &n);
    esp_err_t err = ESP_ERR_NOT_FOUND;
    for (int i = 0; i < n; i++) {
        if (strcmp(list[i].ssid, ssid) == 0) {
            strlcpy(pass_out, list[i].pass, cap);
            err = ESP_OK;
            break;
        }
    }
    free(list);
    return err;
}

esp_err_t prov_storage_add(const char *ssid, const char *pass)
{
    if (!ssid || !ssid[0]) return ESP_ERR_INVALID_ARG;
    if (!pass) pass = "";
    if (strlen(ssid) >= WIFIX_SSID_MAX || strlen(pass) >= WIFIX_PASS_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }

    prov_creds_t *list = calloc(s_max_networks, sizeof(prov_creds_t));
    if (!list) return ESP_ERR_NO_MEM;
    int n = 0;
    prov_storage_load_all(list, s_max_networks, &n);

    for (int i = 0; i < n; i++) {
        if (strcmp(list[i].ssid, ssid) == 0) {
            strlcpy(list[i].pass, pass, sizeof(list[i].pass));
            esp_err_t err = write_list(list, n);
            free(list);
            if (err == ESP_OK) ESP_LOGI(TAG, "更新凭证 %s", ssid);
            return err;
        }
    }

    if (n >= s_max_networks) {
        free(list);
        ESP_LOGW(TAG, "已达上限 %d 条", s_max_networks);
        return ESP_ERR_NO_MEM;
    }
    strlcpy(list[n].ssid, ssid, sizeof(list[n].ssid));
    strlcpy(list[n].pass, pass, sizeof(list[n].pass));
    n++;
    esp_err_t err = write_list(list, n);
    free(list);
    if (err == ESP_OK) ESP_LOGI(TAG, "新增凭证 %s（共 %d 条）", ssid, n);
    return err;
}

esp_err_t prov_storage_remove(const char *ssid)
{
    if (!ssid || !ssid[0]) return ESP_ERR_INVALID_ARG;
    prov_creds_t *list = calloc(s_max_networks, sizeof(prov_creds_t));
    if (!list) return ESP_ERR_NO_MEM;
    int n = 0;
    prov_storage_load_all(list, s_max_networks, &n);

    int found = -1;
    for (int i = 0; i < n; i++) {
        if (strcmp(list[i].ssid, ssid) == 0) { found = i; break; }
    }
    if (found < 0) {
        free(list);
        return ESP_ERR_NOT_FOUND;
    }
    for (int i = found; i < n - 1; i++) list[i] = list[i + 1];
    n--;
    esp_err_t err = write_list(list, n);
    free(list);
    if (err == ESP_OK) ESP_LOGI(TAG, "删除凭证 %s（剩 %d 条）", ssid, n);
    return err;
}

esp_err_t prov_storage_clear_all(void)
{
    esp_err_t err = write_list(NULL, 0);
    if (err == ESP_OK) ESP_LOGW(TAG, "全部凭证已清空");
    return err;
}

// ---- 管理账密 ----

// 常量时间字符串比较（防 timing 侧信道）
static bool ct_streq(const char *a, const char *b)
{
    if (!a || !b) return false;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < la; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool prov_storage_check_credentials(const char *user, const char *pass)
{
    if (!user || !pass) return false;
    nvs_handle_t h;
    if (open_ro(&h) != ESP_OK) return false;
    char nu[WIFIX_USER_MAX] = {0};
    char np[WIFIX_PASS_MAX] = {0};
    size_t l;
    l = sizeof(nu); nvs_get_str(h, KEY_USER, nu, &l);
    l = sizeof(np); nvs_get_str(h, KEY_PASS, np, &l);
    nvs_close(h);
    bool ok_u = ct_streq(user, nu);
    bool ok_p = ct_streq(pass, np);
    return ok_u && ok_p;
}

esp_err_t prov_storage_set_credentials(const char *user, const char *pass)
{
    if (!user || !pass || !user[0] || !pass[0]) return ESP_ERR_INVALID_ARG;
    if (strlen(user) >= WIFIX_USER_MAX || strlen(pass) >= WIFIX_PASS_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    nvs_handle_t h;
    esp_err_t err = open_rw(&h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, KEY_USER, user);
    if (err == ESP_OK) err = nvs_set_str(h, KEY_PASS, pass);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK) ESP_LOGI(TAG, "管理账密已更新");
    else ESP_LOGE(TAG, "管理账密保存失败 err=0x%x", err);
    return err;
}

esp_err_t prov_storage_get_username(char *out, size_t cap)
{
    if (cap == 0) return ESP_ERR_INVALID_SIZE;
    out[0] = 0;
    nvs_handle_t h;
    if (open_ro(&h) != ESP_OK) return ESP_FAIL;
    size_t l = cap;
    esp_err_t err = nvs_get_str(h, KEY_USER, out, &l);
    nvs_close(h);
    return err;
}

// ---- force flag + power-cycle ----

bool prov_storage_consume_force_flag(void)
{
    nvs_handle_t h;
    if (open_rw(&h) != ESP_OK) return false;
    uint8_t v = 0;
    nvs_get_u8(h, KEY_FORCE, &v);
    if (v) {
        nvs_set_u8(h, KEY_FORCE, 0);
        nvs_commit(h);
    }
    nvs_close(h);
    return v != 0;
}

void prov_storage_set_force_flag(void)
{
    nvs_handle_t h;
    if (open_rw(&h) != ESP_OK) return;
    nvs_set_u8(h, KEY_FORCE, 1);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGW(TAG, "force_prov flag 已置位");
}

static esp_timer_handle_t s_stable_timer;

static void stable_clear_cb(void *arg)
{
    nvs_handle_t h;
    if (open_rw(&h) == ESP_OK) {
        nvs_set_u8(h, KEY_PWRCNT, 0);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "稳定启动，power-cycle 计数清零");
    }
    if (s_stable_timer) {
        esp_timer_delete(s_stable_timer);
        s_stable_timer = NULL;
    }
}

bool prov_storage_power_cycle_check(int threshold, int stable_ms)
{
    if (threshold <= 0) return false;

    nvs_handle_t h;
    if (open_rw(&h) != ESP_OK) return false;
    uint8_t n = 0;
    nvs_get_u8(h, KEY_PWRCNT, &n);
    n++;
    nvs_set_u8(h, KEY_PWRCNT, n);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "power-cycle 计数 = %d/%d", n, threshold);

    if (n >= threshold) {
        if (open_rw(&h) == ESP_OK) {
            nvs_set_u8(h, KEY_PWRCNT, 0);
            nvs_set_u8(h, KEY_FORCE, 1);
            nvs_commit(h);
            nvs_close(h);
        }
        ESP_LOGW(TAG, "%d 次连续短电启动，下次启动进配网（凭证保留）", threshold);
        return true;
    }

    esp_timer_create_args_t args = {
        .callback = stable_clear_cb,
        .name = "wifix_stable",
    };
    if (esp_timer_create(&args, &s_stable_timer) == ESP_OK && s_stable_timer) {
        esp_timer_start_once(s_stable_timer, (uint64_t)stable_ms * 1000);
    }
    return false;
}
