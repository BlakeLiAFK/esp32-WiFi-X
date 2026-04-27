idf_component_register(
    SRCS
        "src/wifix.c"
        "src/prov_storage.c"
        "src/prov_sta.c"
        "src/prov_softap.c"
        "src/prov_http.c"
        "src/prov_auth.c"
        "src/dns_hijack.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    PRIV_REQUIRES nvs_flash esp_wifi esp_event esp_netif lwip
                  esp_http_server esp_timer mbedtls driver
    EMBED_TXTFILES "src/prov_page.html"
)
