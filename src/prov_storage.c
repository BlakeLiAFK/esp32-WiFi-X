// 多 WiFi 凭证 + 管理账密 + power-cycle/force 标志位
//
// NVS 布局（namespace = "wifix"）：
//   count     u8         已存网络数 (0..MAX)
//   s0..s15   str        SSID
//   p0..p15   str        密码（可空）
//   au        str        管理界面用户名
//   ap        str        管理界面密码
//   force     u8         "下次启动进配网" flag
//   pwr       u8         power-cycle 短电启动计数

#include "prov_internal.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "wifix.store";

#define KEY_COUNT     "count"
#define KEY_USER      "au"
#define KEY_PASS      "ap"
#define KEY_FORCE     "force"
#define KEY_PWRCNT    "pwr"

static int s_max_networks = 16;

static void k_ssid(int i, char *out) { snprintf(out, 8, "s%d", i); }
static void k_pass(int i, char *out) { snprintf(out, 8, "p%d", i); }

static esp_err_t open_rw(nvs_handle_t *h)
{
    return nvs_open(PROV_NVS_NAMESPACE, NVS_READWRITE, h);
}

static esp_err_t open_ro(nvs_handle_t *h)
{
    return nvs_open(PROV_NVS_NAMESPACE, NVS_READONLY, h);
}

esp_err_t prov_storage_init(const char *default_user, const char *default_pass)
{
    s_max_networks = prov_rt()->max_networks;

    nvs_handle_t h;
    esp_err_t err = open_rw(&h);
    if (err != ESP_OK) return err;

    // 首次烧录：写入默认账密
    size_t len = 0;
    if (nvs_get_str(h, KEY_USER, NULL, &len) == ESP_ERR_NVS_NOT_FOUND) {
        nvs_set_str(h, KEY_USER, default_user ? default_user : "admin");
        nvs_set_str(h, KEY_PASS, default_pass ? default_pass : "admin");
        nvs_commit(h);
        ESP_LOGI(TAG, "首次启动，写入默认账密 %s/****", default_user ? default_user : "admin");
    }
    nvs_close(h);
    return ESP_OK;
}

int prov_storage_count(void)
{
    nvs_handle_t h;
    if (open_ro(&h) != ESP_OK) return 0;
    uint8_t n = 0;
    nvs_get_u8(h, KEY_COUNT, &n);
    nvs_close(h);
    if (n > s_max_networks) n = s_max_networks;
    return n;
}

esp_err_t prov_storage_load_all(prov_creds_t *out, int cap, int *count_out)
{
    nvs_handle_t h;
    esp_err_t err = open_ro(&h);
    if (err != ESP_OK) return err;

    uint8_t n = 0;
    nvs_get_u8(h, KEY_COUNT, &n);
    if (n > s_max_networks) n = s_max_networks;
    int outn = 0;
    char k[8];
    for (int i = 0; i < n && outn < cap; i++) {
        size_t l;
        k_ssid(i, k);
        l = sizeof(out[outn].ssid);
        if (nvs_get_str(h, k, out[outn].ssid, &l) != ESP_OK) continue;
        if (out[outn].ssid[0] == 0) continue;
        k_pass(i, k);
        l = sizeof(out[outn].pass);
        if (nvs_get_str(h, k, out[outn].pass, &l) != ESP_OK) {
            out[outn].pass[0] = 0;
        }
        outn++;
    }
    nvs_close(h);
    if (count_out) *count_out = outn;
    return ESP_OK;
}

esp_err_t prov_storage_get_pass(const char *ssid, char *pass_out, size_t cap)
{
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

// 重写整个列表回 NVS（删除多余键）
static esp_err_t rewrite_all(prov_creds_t *list, int n)
{
    nvs_handle_t h;
    esp_err_t err = open_rw(&h);
    if (err != ESP_OK) return err;

    char k[8];
    // 写当前
    for (int i = 0; i < n; i++) {
        k_ssid(i, k);
        nvs_set_str(h, k, list[i].ssid);
        k_pass(i, k);
        nvs_set_str(h, k, list[i].pass);
    }
    // 清掉多余的旧条目（下标 n..max-1）
    for (int i = n; i < s_max_networks; i++) {
        k_ssid(i, k);
        nvs_erase_key(h, k);
        k_pass(i, k);
        nvs_erase_key(h, k);
    }
    nvs_set_u8(h, KEY_COUNT, (uint8_t)n);
    err = nvs_commit(h);
    nvs_close(h);
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

    // 同名覆盖
    for (int i = 0; i < n; i++) {
        if (strcmp(list[i].ssid, ssid) == 0) {
            strlcpy(list[i].pass, pass, sizeof(list[i].pass));
            esp_err_t err = rewrite_all(list, n);
            free(list);
            ESP_LOGI(TAG, "更新凭证 %s", ssid);
            return err;
        }
    }

    if (n >= s_max_networks) {
        free(list);
        ESP_LOGW(TAG, "已达上限 %d 条，无法新增", s_max_networks);
        return ESP_ERR_NO_MEM;
    }
    strlcpy(list[n].ssid, ssid, sizeof(list[n].ssid));
    strlcpy(list[n].pass, pass, sizeof(list[n].pass));
    n++;
    esp_err_t err = rewrite_all(list, n);
    free(list);
    ESP_LOGI(TAG, "新增凭证 %s（共 %d 条）", ssid, n);
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
    esp_err_t err = rewrite_all(list, n);
    free(list);
    ESP_LOGI(TAG, "删除凭证 %s（剩 %d 条）", ssid, n);
    return err;
}

esp_err_t prov_storage_clear_all(void)
{
    nvs_handle_t h;
    if (open_rw(&h) != ESP_OK) return ESP_FAIL;
    char k[8];
    for (int i = 0; i < s_max_networks; i++) {
        k_ssid(i, k); nvs_erase_key(h, k);
        k_pass(i, k); nvs_erase_key(h, k);
    }
    nvs_set_u8(h, KEY_COUNT, 0);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGW(TAG, "全部凭证已清空");
    return ESP_OK;
}

// ---- 管理账密 ----

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
    return strcmp(user, nu) == 0 && strcmp(pass, np) == 0;
}

esp_err_t prov_storage_set_credentials(const char *user, const char *pass)
{
    if (!user || !pass || !user[0] || !pass[0]) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = open_rw(&h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, KEY_USER, user);
    if (err == ESP_OK) err = nvs_set_str(h, KEY_PASS, pass);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK) ESP_LOGI(TAG, "管理账密已更新");
    return err;
}

esp_err_t prov_storage_get_username(char *out, size_t cap)
{
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

static void stable_clear_cb(void *arg)
{
    nvs_handle_t h;
    if (open_rw(&h) == ESP_OK) {
        nvs_set_u8(h, KEY_PWRCNT, 0);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "稳定启动，power-cycle 计数清零");
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

    esp_timer_handle_t t;
    esp_timer_create_args_t args = {
        .callback = stable_clear_cb,
        .name = "wifix_stable",
    };
    esp_timer_create(&args, &t);
    esp_timer_start_once(t, (uint64_t)stable_ms * 1000);
    return false;
}
