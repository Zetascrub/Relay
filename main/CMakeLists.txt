idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       REQUIRES app_update driver esp_eth esp_event esp_http_server
                                esp_netif esp_partition esp_timer json lwip mbedtls
                                mdns nvs_flash)
