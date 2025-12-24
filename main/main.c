#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_eth.h"
#include "esp_eth_com.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"
#include "lwip/netdb.h"
#include "lwip/netif.h"
#include "lwip/prot/ethernet.h"
#include "lwip/sockets.h"

#include <inttypes.h>

static const char *TAG = "eth_debug";
static esp_eth_handle_t s_eth_handle = NULL;
static esp_eth_phy_t *s_phy = NULL;
static volatile bool s_link_up = false;
static volatile uint32_t s_link_up_events = 0;
static esp_netif_t *s_netif = NULL;
static volatile bool s_http_test_started = false;
static volatile bool s_got_ip_once = false;

#define HTTP_TEST_URL "http://ash-speed.hetzner.com/100MB.bin"
// Larger buffer helps keep TCP receive window open and reduces per-read overhead.
// Keep in internal RAM for best throughput.
#define HTTP_TEST_RX_BUF_SIZE (64 * 1024)
#define HTTP_TEST_REPORT_INTERVAL_MS 1000

// Parsed from HTTP_TEST_URL (kept explicit to avoid pulling in a URL parser)
#define HTTP_TEST_HOST "ash-speed.hetzner.com"
#define HTTP_TEST_PATH "/100MB.bin"
#define HTTP_TEST_PORT 80

// The 100M probe restarts the Ethernet driver and can disrupt DHCP/HTTP tests.
// Keep it OFF by default; enable only when you are explicitly diagnosing 100M.
#define ETH_ENABLE_100M_PROBE 0

// If DHCP never completes but link is UP, optionally apply a static IP so we can still
// verify traffic with the HTTP download test.
// Adjust these values to match your LAN.
#define ETH_STATIC_FALLBACK_ENABLE 1
#define ETH_STATIC_FALLBACK_IP_A   192
#define ETH_STATIC_FALLBACK_IP_B   168
#define ETH_STATIC_FALLBACK_IP_C   16
#define ETH_STATIC_FALLBACK_IP_D   222
#define ETH_STATIC_FALLBACK_GW_A   192
#define ETH_STATIC_FALLBACK_GW_B   168
#define ETH_STATIC_FALLBACK_GW_C   16
#define ETH_STATIC_FALLBACK_GW_D   1
#define ETH_STATIC_FALLBACK_MASK_A 255
#define ETH_STATIC_FALLBACK_MASK_B 255
#define ETH_STATIC_FALLBACK_MASK_C 255
#define ETH_STATIC_FALLBACK_MASK_D 0
// Default DNS to the configured gateway (common home/office router setup).
// If your router doesn't provide DNS, set these to a reachable DNS server.
#define ETH_STATIC_FALLBACK_DNS_A  ETH_STATIC_FALLBACK_GW_A
#define ETH_STATIC_FALLBACK_DNS_B  ETH_STATIC_FALLBACK_GW_B
#define ETH_STATIC_FALLBACK_DNS_C  ETH_STATIC_FALLBACK_GW_C
#define ETH_STATIC_FALLBACK_DNS_D  ETH_STATIC_FALLBACK_GW_D

typedef enum {
    ETH_MODE_AUTONEG = 0,
    ETH_MODE_FORCE_10H,
    ETH_MODE_FORCE_100F,
} eth_test_mode_t;

static volatile eth_test_mode_t s_mode = ETH_MODE_AUTONEG;
static volatile eth_speed_t s_last_link_speed = ETH_SPEED_10M;
static volatile eth_duplex_t s_last_link_duplex = ETH_DUPLEX_HALF;

void http_download_task(void *param);
static void start_http_test_once(void);

static void http_speed_test_raw_socket(void);

typedef struct {
    bool active;
    bool done;
    bool success;
    uint32_t started_link_up_events;
    uint32_t deadline_ms;
} eth_probe_t;

static eth_probe_t s_probe_100m = {0};

static bool log_ip_info_once(const char *prefix)
{
    if (!s_netif) {
        ESP_LOGW(TAG, "%s: netif=null", prefix ? prefix : "IP");
        return false;
    }

    esp_netif_ip_info_t ip_info;
    memset(&ip_info, 0, sizeof(ip_info));
    esp_err_t err = esp_netif_get_ip_info(s_netif, &ip_info);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "%s: esp_netif_get_ip_info failed: %s", prefix ? prefix : "IP", esp_err_to_name(err));
        return false;
    }

    const bool has_ip = (ip_info.ip.addr != 0);
    ESP_LOGI(TAG, "%s: ip=" IPSTR " netmask=" IPSTR " gw=" IPSTR,
             prefix ? prefix : "IP",
             IP2STR(&ip_info.ip), IP2STR(&ip_info.netmask), IP2STR(&ip_info.gw));
    return has_ip;
}

static void log_dns_info_once(void)
{
    if (!s_netif) {
        ESP_LOGW(TAG, "DNS: netif=null");
        return;
    }

    esp_netif_dns_info_t dns;
    memset(&dns, 0, sizeof(dns));
    if (esp_netif_get_dns_info(s_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK && dns.ip.type == ESP_IPADDR_TYPE_V4) {
        ESP_LOGI(TAG, "DNS: main=" IPSTR, IP2STR(&dns.ip.u_addr.ip4));
    } else {
        ESP_LOGI(TAG, "DNS: main=<unset>");
    }

    memset(&dns, 0, sizeof(dns));
    if (esp_netif_get_dns_info(s_netif, ESP_NETIF_DNS_BACKUP, &dns) == ESP_OK && dns.ip.type == ESP_IPADDR_TYPE_V4) {
        ESP_LOGI(TAG, "DNS: backup=" IPSTR, IP2STR(&dns.ip.u_addr.ip4));
    } else {
        ESP_LOGI(TAG, "DNS: backup=<unset>");
    }
}

static void arp_probe_once(const char *label, const ip4_addr_t *target)
{
    if (!label || !target) {
        return;
    }

    struct netif *lwip_netif = NULL;
    if (s_netif) {
        lwip_netif = (struct netif *)esp_netif_get_netif_impl(s_netif);
    }
    if (!lwip_netif) {
        lwip_netif = netif_default;
    }
    if (!lwip_netif) {
        ESP_LOGW(TAG, "ARP: no lwIP netif (can't probe %s)", label);
        return;
    }

    ESP_LOGI(TAG, "ARP: probing %s (" IPSTR ") on %c%c", label, IP2STR(target),
             (char)lwip_netif->name[0], (char)lwip_netif->name[1]);

    (void)etharp_request(lwip_netif, target);
    vTaskDelay(pdMS_TO_TICKS(200));

    struct eth_addr *eth_ret = NULL;
    const ip4_addr_t *ip_ret = NULL;
    const s8_t idx = etharp_find_addr(lwip_netif, target, &eth_ret, &ip_ret);
    if (idx >= 0 && eth_ret) {
        ESP_LOGI(TAG, "ARP: %s resolved -> %02X:%02X:%02X:%02X:%02X:%02X", label,
                 eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
                 eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
    } else {
        ESP_LOGW(TAG, "ARP: %s not resolved (wrong GW/DNS IP, or no TX/RX packets)", label);
    }
}

static void dhcp_start_and_log(void)
{
    if (!s_netif) {
        ESP_LOGW(TAG, "DHCP: netif=null");
        return;
    }

    esp_err_t err = esp_netif_dhcpc_start(s_netif);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "DHCP: start requested");
    } else if (err == ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
        ESP_LOGI(TAG, "DHCP: already started");
    } else {
        ESP_LOGW(TAG, "DHCP: start failed: %s", esp_err_to_name(err));
    }

    esp_netif_dhcp_status_t st = ESP_NETIF_DHCP_INIT;
    err = esp_netif_dhcpc_get_status(s_netif, &st);
    if (err == ESP_OK) {
        const char *st_s = (st == ESP_NETIF_DHCP_STARTED) ? "STARTED" :
                           (st == ESP_NETIF_DHCP_STOPPED) ? "STOPPED" :
                           (st == ESP_NETIF_DHCP_INIT) ? "INIT" : "UNKNOWN";
        ESP_LOGI(TAG, "DHCP: status=%s", st_s);
    }
}

static bool apply_static_ip_fallback(void)
{
#if !ETH_STATIC_FALLBACK_ENABLE
    return false;
#else
    if (!s_netif) {
        ESP_LOGW(TAG, "Static IP: netif=null");
        return false;
    }

    // Stop DHCP if it was running.
    (void)esp_netif_dhcpc_stop(s_netif);

    esp_netif_ip_info_t ip_info;
    memset(&ip_info, 0, sizeof(ip_info));
    IP4_ADDR(&ip_info.ip, ETH_STATIC_FALLBACK_IP_A, ETH_STATIC_FALLBACK_IP_B, ETH_STATIC_FALLBACK_IP_C, ETH_STATIC_FALLBACK_IP_D);
    IP4_ADDR(&ip_info.gw, ETH_STATIC_FALLBACK_GW_A, ETH_STATIC_FALLBACK_GW_B, ETH_STATIC_FALLBACK_GW_C, ETH_STATIC_FALLBACK_GW_D);
    IP4_ADDR(&ip_info.netmask, ETH_STATIC_FALLBACK_MASK_A, ETH_STATIC_FALLBACK_MASK_B, ETH_STATIC_FALLBACK_MASK_C, ETH_STATIC_FALLBACK_MASK_D);

    esp_err_t err = esp_netif_set_ip_info(s_netif, &ip_info);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Static IP: esp_netif_set_ip_info failed: %s", esp_err_to_name(err));
        return false;
    }

    esp_netif_dns_info_t dns;
    memset(&dns, 0, sizeof(dns));
    IP4_ADDR(&dns.ip.u_addr.ip4, ETH_STATIC_FALLBACK_DNS_A, ETH_STATIC_FALLBACK_DNS_B, ETH_STATIC_FALLBACK_DNS_C, ETH_STATIC_FALLBACK_DNS_D);
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    err = esp_netif_set_dns_info(s_netif, ESP_NETIF_DNS_MAIN, &dns);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Static IP: esp_netif_set_dns_info failed: %s", esp_err_to_name(err));
    }

    // Also set a backup DNS (Cloudflare) as a secondary option.
    memset(&dns, 0, sizeof(dns));
    IP4_ADDR(&dns.ip.u_addr.ip4, 1, 1, 1, 1);
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    err = esp_netif_set_dns_info(s_netif, ESP_NETIF_DNS_BACKUP, &dns);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Static IP: esp_netif_set_dns_info(BACKUP) failed: %s", esp_err_to_name(err));
    }

    ESP_LOGW(TAG, "Static IP fallback applied (edit ETH_STATIC_FALLBACK_* macros if needed)");
    (void)log_ip_info_once("IP (static)");
    log_dns_info_once();

    // Basic L2 sanity check: can we resolve the gateway MAC via ARP?
    // If this fails, DHCP/DNS/HTTP will also fail because packets aren't flowing.
    arp_probe_once("gateway", (const ip4_addr_t *)&ip_info.gw);

    return true;
#endif
}

static esp_err_t apply_eth_mode(bool autoneg, eth_speed_t speed, eth_duplex_t duplex)
{
    if (!s_eth_handle) {
        return ESP_ERR_INVALID_STATE;
    }

    // Stop before changing negotiation/speed/duplex per ESP-IDF requirements.
    esp_err_t err = esp_eth_stop(s_eth_handle);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "esp_eth_stop failed: %s", esp_err_to_name(err));
    }

    ESP_ERROR_CHECK(esp_eth_ioctl(s_eth_handle, ETH_CMD_S_AUTONEGO, &autoneg));
    if (!autoneg) {
        ESP_ERROR_CHECK(esp_eth_ioctl(s_eth_handle, ETH_CMD_S_SPEED, &speed));
        ESP_ERROR_CHECK(esp_eth_ioctl(s_eth_handle, ETH_CMD_S_DUPLEX_MODE, &duplex));
    }

    if (autoneg) {
        s_mode = ETH_MODE_AUTONEG;
    } else if (speed == ETH_SPEED_100M && duplex == ETH_DUPLEX_FULL) {
        s_mode = ETH_MODE_FORCE_100F;
    } else {
        s_mode = ETH_MODE_FORCE_10H;
    }

    ESP_ERROR_CHECK(esp_eth_start(s_eth_handle));
    return ESP_OK;
}

static esp_err_t phy_read_reg(uint32_t reg_addr, uint32_t *out_value)
{
    if (!s_eth_handle || !out_value) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_eth_phy_reg_rw_data_t rw = {
        .reg_addr = reg_addr,
        .reg_value_p = out_value,
    };
    return esp_eth_ioctl(s_eth_handle, ETH_CMD_READ_PHY_REG, &rw);
}

static void log_phy_status_once(void)
{
    // IEEE 802.3 standard registers
    // 0: BMCR, 1: BMSR, 4: ANAR, 5: ANLPAR, 2/3: PHY ID
    uint32_t bmcr = 0, bmsr1 = 0, bmsr2 = 0, anar = 0, anlpar = 0, phyid1 = 0, phyid2 = 0;

    (void)phy_read_reg(0, &bmcr);
    // BMSR link status is latched-low on some PHYs; read twice.
    (void)phy_read_reg(1, &bmsr1);
    (void)phy_read_reg(1, &bmsr2);
    (void)phy_read_reg(2, &phyid1);
    (void)phy_read_reg(3, &phyid2);
    (void)phy_read_reg(4, &anar);
    (void)phy_read_reg(5, &anlpar);

    const bool link_up = (bmsr2 & (1u << 2)) != 0;
    const bool aneg_complete = (bmsr2 & (1u << 5)) != 0;
    const bool aneg_enable = (bmcr & (1u << 12)) != 0;

    ESP_LOGI(TAG, "PHY: BMCR=0x%04" PRIx32 " BMSR=0x%04" PRIx32 " (prev=0x%04" PRIx32 ") link=%d aneg_en=%d aneg_done=%d",
             bmcr & 0xFFFF, bmsr2 & 0xFFFF, bmsr1 & 0xFFFF,
             (int)link_up, (int)aneg_enable, (int)aneg_complete);
    ESP_LOGI(TAG, "PHY: ID1=0x%04" PRIx32 " ID2=0x%04" PRIx32 " ANAR=0x%04" PRIx32 " ANLPAR=0x%04" PRIx32,
             phyid1 & 0xFFFF, phyid2 & 0xFFFF, anar & 0xFFFF, anlpar & 0xFFFF);
}

static void log_link_params(esp_eth_handle_t eth_handle)
{
    eth_speed_t speed = ETH_SPEED_10M;
    eth_duplex_t duplex = ETH_DUPLEX_HALF;

    if (esp_eth_ioctl(eth_handle, ETH_CMD_G_SPEED, &speed) != ESP_OK) {
        ESP_LOGW(TAG, "Failed to read link speed");
    }
    if (esp_eth_ioctl(eth_handle, ETH_CMD_G_DUPLEX_MODE, &duplex) != ESP_OK) {
        ESP_LOGW(TAG, "Failed to read duplex mode");
    }

    const char *speed_s = (speed == ETH_SPEED_100M) ? "100M" : "10M";
    const char *duplex_s = (duplex == ETH_DUPLEX_FULL) ? "FULL" : "HALF";
    ESP_LOGI(TAG, "Link: %s %s", speed_s, duplex_s);
}

static void dump_phy_regs(void) {
    if (!s_eth_handle) {
        ESP_LOGW(TAG, "Skip PHY dump (handle=null)");
        return;
    }

    // ESP-IDF v5.5 expects esp_eth_phy_reg_rw_data_t for ETH_CMD_READ/WRITE_PHY_REG.
    // The PHY address is configured separately (ETH_CMD_S_PHY_ADDR / ETH_CMD_G_PHY_ADDR).
    for (int reg_addr = 0; reg_addr <= 6; ++reg_addr) {
        uint32_t reg_value = 0;
        esp_eth_phy_reg_rw_data_t rw = {
            .reg_addr = (uint32_t)reg_addr,
            .reg_value_p = &reg_value,
        };
        if (esp_eth_ioctl(s_eth_handle, ETH_CMD_READ_PHY_REG, &rw) == ESP_OK) {
            ESP_LOGI(TAG, "PHY reg %02d = 0x%04" PRIx32, reg_addr, reg_value & 0xFFFF);
        } else {
            ESP_LOGW(TAG, "PHY reg %02d read failed", reg_addr);
        }
    }
}

static void on_got_ip(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    const ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    ESP_LOGI(TAG, "Netmask: " IPSTR ", Gateway: " IPSTR,
             IP2STR(&event->ip_info.netmask), IP2STR(&event->ip_info.gw));
    s_got_ip_once = true;

    // Start HTTP download test once, after we have a valid IP.
    start_http_test_once();
}

static void start_http_test_once(void)
{
    if (s_http_test_started) {
        return;
    }
    s_http_test_started = true;
    // Give the download task a higher priority so it can drain the TCP recv mailbox fast.
    BaseType_t ok = xTaskCreate(http_download_task, "http_test", 8192, NULL, 12, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "Failed to create http_test task");
    }
}

static void on_lost_ip(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    ESP_LOGW(TAG, "Lost IP");
}

void http_download_task(void *param)
{
    (void)param;

    http_speed_test_raw_socket();
    vTaskDelete(NULL);
}

static void http_speed_test_raw_socket(void)
{
    ESP_LOGI(TAG, "HTTP test: downloading %s", HTTP_TEST_URL);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", HTTP_TEST_PORT);

    struct addrinfo *res = NULL;
    const int gai = getaddrinfo(HTTP_TEST_HOST, port_str, &hints, &res);
    if (gai != 0 || res == NULL) {
        ESP_LOGE(TAG, "HTTP test: DNS failed for %s: %d", HTTP_TEST_HOST, gai);
        return;
    }

    int sock = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        sock = (int)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
            continue;
        }
        if (connect(sock, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    res = NULL;

    if (sock < 0) {
        ESP_LOGE(TAG, "HTTP test: connect failed");
        return;
    }

    // Best-effort: allow lwIP to buffer more incoming data per socket.
    // (May be clamped internally depending on lwIP configuration.)
    {
        const int rcvbuf = 256 * 1024;
        (void)setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }

    struct timeval tv;
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char req[256];
    const int req_len = snprintf(req, sizeof(req),
                                 "GET %s HTTP/1.1\r\n"
                                 "Host: %s\r\n"
                                 "User-Agent: esp32p4-eth-speedtest\r\n"
                                 "Connection: close\r\n\r\n",
                                 HTTP_TEST_PATH, HTTP_TEST_HOST);
    if (req_len <= 0 || req_len >= (int)sizeof(req)) {
        ESP_LOGE(TAG, "HTTP test: request build failed");
        close(sock);
        return;
    }

    int sent = 0;
    while (sent < req_len) {
        const int w = (int)send(sock, req + sent, req_len - sent, 0);
        if (w <= 0) {
            ESP_LOGE(TAG, "HTTP test: send failed");
            close(sock);
            return;
        }
        sent += w;
    }

    uint8_t *buf = (uint8_t *)heap_caps_malloc(HTTP_TEST_RX_BUF_SIZE, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!buf) {
        ESP_LOGE(TAG, "HTTP test: failed to alloc rx buffer");
        close(sock);
        return;
    }

    char header_buf[2048];
    size_t header_len = 0;
    bool header_done = false;
    int64_t content_length = -1;

    const int64_t start_us = esp_timer_get_time();
    int64_t last_report_us = start_us;
    int64_t last_report_total = 0;
    int64_t total = 0;

    while (true) {
        const int r = (int)recv(sock, (char *)buf, HTTP_TEST_RX_BUF_SIZE, 0);
        if (r < 0) {
            ESP_LOGE(TAG, "HTTP test: recv error");
            break;
        }
        if (r == 0) {
            break;
        }

        int payload_start = 0;
        if (!header_done) {
            const size_t copy_n = (header_len < sizeof(header_buf) - 1)
                                      ? (size_t)((r < (int)(sizeof(header_buf) - 1 - header_len)) ? r : (int)(sizeof(header_buf) - 1 - header_len))
                                      : 0;
            if (copy_n > 0) {
                memcpy(header_buf + header_len, buf, copy_n);
                header_len += copy_n;
                header_buf[header_len] = '\0';

                char *end = strstr(header_buf, "\r\n\r\n");
                if (end) {
                    header_done = true;
                    payload_start = (int)((end + 4) - header_buf);

                    char *cl = strcasestr(header_buf, "\r\nContent-Length:");
                    if (cl) {
                        cl += 2; // skip leading CRLF
                        cl = strchr(cl, ':');
                        if (cl) {
                            cl++;
                            while (*cl == ' ') cl++;
                            content_length = atoll(cl);
                        }
                    }

                    // The payload bytes we already have in header_buf are part of this recv.
                    const int header_consumed_from_this_recv = (int)copy_n - payload_start;
                    if (header_consumed_from_this_recv < 0) {
                        // Header end not fully contained in the copied part.
                        payload_start = 0;
                    } else {
                        // For this recv, the payload starts at payload_start within header_buf, which corresponds to
                        // the same offset in buf (since we copied from the beginning).
                    }

                    ESP_LOGI(TAG, "HTTP test: header received (content_length=%lld)", (long long)content_length);
                }
            }
        }

        if (header_done) {
            // If header end was within the copied portion, payload starts at that offset for this recv.
            // Otherwise, payload is the whole recv buffer.
            int body_offset = 0;
            if (payload_start > 0 && payload_start <= r) {
                body_offset = payload_start;
            }
            total += (r - body_offset);
        }

        const int64_t now_us = esp_timer_get_time();
        if (now_us - last_report_us >= (int64_t)HTTP_TEST_REPORT_INTERVAL_MS * 1000) {
            const double elapsed_s = (now_us - start_us) / 1000000.0;
            const double mb = total / (1024.0 * 1024.0);
            const double avg_mbps = (total * 8.0) / (elapsed_s * 1000.0 * 1000.0);

            const int64_t delta_bytes = total - last_report_total;
            const double delta_s = (now_us - last_report_us) / 1000000.0;
            const double inst_mbps = (delta_s > 0) ? (delta_bytes * 8.0) / (delta_s * 1000.0 * 1000.0) : 0.0;

            ESP_LOGI(TAG, "HTTP test: received %.2f MiB in %.1fs (inst %.2f Mbps, avg %.2f Mbps)", mb, elapsed_s, inst_mbps, avg_mbps);
            last_report_us = now_us;
            last_report_total = total;
        }

        if (content_length > 0 && total >= content_length) {
            break;
        }
    }

    const int64_t end_us = esp_timer_get_time();
    const double elapsed_s = (end_us - start_us) / 1000000.0;
    const double mb = total / (1024.0 * 1024.0);
    const double mbps = (total * 8.0) / (elapsed_s * 1000.0 * 1000.0);
    ESP_LOGI(TAG, "HTTP test: DONE %.2f MiB in %.2fs (avg %.2f Mbps)", mb, elapsed_s, mbps);

    heap_caps_free(buf);
    close(sock);
}

static void on_eth_event(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    const esp_eth_handle_t eth_handle = *(esp_eth_handle_t *)event_data;
    switch (event_id) {
    case ETHERNET_EVENT_CONNECTED:
        ESP_LOGI(TAG, "Ethernet link up");
        s_link_up = true;
        s_link_up_events++;
        {
            eth_speed_t speed = ETH_SPEED_10M;
            eth_duplex_t duplex = ETH_DUPLEX_HALF;
            (void)esp_eth_ioctl(eth_handle, ETH_CMD_G_SPEED, &speed);
            (void)esp_eth_ioctl(eth_handle, ETH_CMD_G_DUPLEX_MODE, &duplex);
            s_last_link_speed = speed;
            s_last_link_duplex = duplex;
        }
        log_link_params(eth_handle);

        // Make DHCP behavior explicit in logs (and re-request start on link-up).
        dhcp_start_and_log();
        (void)log_ip_info_once("IP (on link-up)");

        // Mark probe success only if we actually linked while in forced 100M/FULL mode.
        if (s_probe_100m.active && s_mode == ETH_MODE_FORCE_100F &&
            s_last_link_speed == ETH_SPEED_100M && s_last_link_duplex == ETH_DUPLEX_FULL) {
            s_probe_100m.success = true;
        }
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "Ethernet link down");
        s_link_up = false;
        break;
    case ETHERNET_EVENT_START:
        ESP_LOGI(TAG, "Ethernet started");
        break;
    case ETHERNET_EVENT_STOP:
        ESP_LOGW(TAG, "Ethernet stopped");
        s_link_up = false;
        break;
    default:
        ESP_LOGD(TAG, "Ethernet event %ld", (long)event_id);
        break;
    }

    if (event_id == ETHERNET_EVENT_CONNECTED) {
        uint8_t mac[6];
        if (esp_eth_ioctl(eth_handle, ETH_CMD_G_MAC_ADDR, mac) == ESP_OK) {
            ESP_LOGI(TAG, "MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            ESP_LOGW(TAG, "Failed to read MAC address");
        }
    }
}

void app_main(void) {
    // Keep logs readable in monitor (global DEBUG quickly floods output and hides the key info).
    esp_log_level_set("*", ESP_LOG_INFO);
    esp_log_level_set(TAG, ESP_LOG_INFO);
    esp_log_level_set("esp_eth", ESP_LOG_INFO);
    esp_log_level_set("esp_netif", ESP_LOG_INFO);
    esp_log_level_set("esp_netif_lwip", ESP_LOG_INFO);
    // Reduce per-chunk logging overhead in the hot download loop.
    esp_log_level_set("esp_http_client", ESP_LOG_WARN);
    esp_log_level_set("transport_base", ESP_LOG_WARN);
    esp_log_level_set("esp_event", ESP_LOG_WARN);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Power-enable the PHY if GPIO51 is wired to the IP101 power rail (matches YAML comment).
    const gpio_config_t power_cfg = {
        .pin_bit_mask = 1ULL << 51,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&power_cfg);
    // Many boards use this pin as PHY power enable or reset.
    // Do a short low->high pulse to ensure the PHY starts in a known state.
    gpio_set_level(51, 0);
    vTaskDelay(pdMS_TO_TICKS(50));
    gpio_set_level(51, 1);
    vTaskDelay(pdMS_TO_TICKS(100));

    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    s_netif = esp_netif_new(&cfg);

    // Configure MAC/PHY for the IP101 over RMII. Pins follow the ESPHome config.
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t esp32_emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    esp32_emac_config.smi_gpio.mdc_num = 31;   // GPIO31
    esp32_emac_config.smi_gpio.mdio_num = 52;  // GPIO52
    esp32_emac_config.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN;
    esp32_emac_config.clock_config.rmii.clock_gpio = 50; // GPIO50 RMII clock in
    mac_config.sw_reset_timeout_ms = 1000;      // Faster recovery on failure.

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = 1;
    phy_config.reset_gpio_num = -1; // No dedicated reset pin wired

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&esp32_emac_config, &mac_config);
    s_phy = esp_eth_phy_new_ip101(&phy_config);

    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, s_phy);

    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &s_eth_handle));

    // Ensure the driver is set to the expected PHY address for subsequent ioctls.
    {
        uint32_t phy_addr = 1;
        ESP_ERROR_CHECK(esp_eth_ioctl(s_eth_handle, ETH_CMD_S_PHY_ADDR, &phy_addr));
        uint32_t phy_addr_readback = 0;
        ESP_ERROR_CHECK(esp_eth_ioctl(s_eth_handle, ETH_CMD_G_PHY_ADDR, &phy_addr_readback));
        ESP_LOGI(TAG, "Configured PHY addr=%" PRIu32, phy_addr_readback);
    }

    // Attach driver to netif
    esp_eth_netif_glue_handle_t glue = esp_eth_new_netif_glue(s_eth_handle);
    ESP_ERROR_CHECK(esp_netif_attach(s_netif, glue));
    ESP_ERROR_CHECK(esp_netif_set_default_netif(s_netif));

    // esp_netif_set_default_netif() should set lwIP's netif_default, but we've observed
    // netif_default remaining NULL in practice. Ensure the underlying lwIP netif is set
    // as default so DNS/sockets have a route.
    {
        struct netif *lwip_netif = (struct netif *)esp_netif_get_netif_impl(s_netif);
        if (lwip_netif) {
            netif_set_default(lwip_netif);
        } else {
            ESP_LOGW(TAG, "lwIP: couldn't get netif impl to set default");
        }
    }

    // Register event handlers for detailed logging
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &on_eth_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &on_got_ip, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_LOST_IP, &on_lost_ip, NULL));

    // Start Ethernet
    ESP_ERROR_CHECK(esp_eth_start(s_eth_handle));

    // If the PHY never reports link-up, try a forced 10M/half mode as a diagnostic.
    // This can help distinguish cable/magnetics/pairing issues (10M may still link)
    // from MDIO/PHY-power issues (PHY registers unreadable) or refclk issues.
    bool forced_mode_applied = false;
    bool tried_10m_full_for_dhcp = false;
    int down_cycles = 0;
    int up_cycles = 0;
    int no_ip_cycles = 0;
    uint32_t boot_ms = 0;

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        boot_ms += 5000;
        ESP_LOGI(TAG, "Link status: %s, heap=%lu", s_link_up ? "UP" : "DOWN",
                 (unsigned long)esp_get_free_heap_size());
        if (!s_link_up) {
            down_cycles++;
            up_cycles = 0;
            no_ip_cycles = 0;
            tried_10m_full_for_dhcp = false;
            log_phy_status_once();
            dump_phy_regs();

            if (!forced_mode_applied && down_cycles >= 3) { // ~15s
                ESP_LOGW(TAG, "No link after %ds -> switching to forced 10M/HALF (autoneg OFF) for diagnostics", down_cycles * 5);
                ESP_ERROR_CHECK(apply_eth_mode(false, ETH_SPEED_10M, ETH_DUPLEX_HALF));
                forced_mode_applied = true;
            }
        } else {
            up_cycles++;
            down_cycles = 0;

            // Periodically show IP status while link is UP.
            const bool has_ip = log_ip_info_once("IP");
            if (!has_ip) {
                no_ip_cycles++;
                if (no_ip_cycles == 1) {
                    dhcp_start_and_log();
                }
                if (no_ip_cycles == 2) { // ~10s without IP
                    ESP_LOGW(TAG, "No IP after ~10s with link UP -> restarting DHCP client");
                    (void)esp_netif_dhcpc_stop(s_netif);
                    dhcp_start_and_log();
                }

                // If we have a PHY-level link but DHCP never works, duplex mismatch is a common culprit.
                // Try forcing 10M/FULL once and restart DHCP to see if packets start flowing.
                if (!tried_10m_full_for_dhcp && forced_mode_applied && no_ip_cycles == 3) { // ~15s
                    tried_10m_full_for_dhcp = true;
                    ESP_LOGW(TAG, "Still no IP with link UP -> trying forced 10M/FULL (autoneg OFF) and restarting DHCP");
                    ESP_ERROR_CHECK(apply_eth_mode(false, ETH_SPEED_10M, ETH_DUPLEX_FULL));
                    (void)esp_netif_dhcpc_stop(s_netif);
                    dhcp_start_and_log();
                }

                if (no_ip_cycles == 4) { // ~20s
                    ESP_LOGE(TAG, "Link is UP but still no IP. Either there is no DHCP server on this port, or traffic is not passing (wiring/magnetics/duplex issue).");
                }

                // After a longer wait, apply a static IP so we can still run the HTTP verification.
                if (no_ip_cycles == 4) { // ~20s
                    ESP_LOGW(TAG, "No DHCP lease after ~20s -> applying static IP fallback to continue verification");
                    if (apply_static_ip_fallback()) {
                        start_http_test_once();
                    }
                }
            } else {
                no_ip_cycles = 0;
            }

            // Once 10M forced mode is stable AND we actually have an IP, probe if forced 100M full is possible.
            // Gating on an IP prevents the probe from interrupting DHCP and our HTTP download verification.
            if (ETH_ENABLE_100M_PROBE && !s_http_test_started &&
                forced_mode_applied && !s_probe_100m.done && !s_probe_100m.active && up_cycles >= 4 && has_ip) { // ~20s of stable link
                ESP_LOGW(TAG, "10M link is stable (with IP) -> probing forced 100M/FULL (autoneg OFF) for 15s");
                s_probe_100m.active = true;
                s_probe_100m.success = false;
                s_probe_100m.started_link_up_events = s_link_up_events;
                s_probe_100m.deadline_ms = boot_ms + 15000;
                ESP_ERROR_CHECK(apply_eth_mode(false, ETH_SPEED_100M, ETH_DUPLEX_FULL));
            }

            if (s_probe_100m.active && boot_ms >= s_probe_100m.deadline_ms) {
                s_probe_100m.active = false;
                s_probe_100m.done = true;
                if (s_probe_100m.success) {
                    ESP_LOGI(TAG, "Forced 100M/FULL link-up confirmed");
                } else {
                    ESP_LOGE(TAG, "Forced 100M/FULL did not produce link-up -> falling back to 10M/HALF. Likely 100M pair/magnetics wiring issue.");
                    ESP_ERROR_CHECK(apply_eth_mode(false, ETH_SPEED_10M, ETH_DUPLEX_HALF));
                }
            }
        }
    }
}
