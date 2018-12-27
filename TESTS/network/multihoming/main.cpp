/*
 * Copyright (c) 2018, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define WIFI 2
#if !defined(MBED_CONF_TARGET_NETWORK_DEFAULT_INTERFACE_TYPE) || \
    (MBED_CONF_TARGET_NETWORK_DEFAULT_INTERFACE_TYPE == WIFI && !defined(MBED_CONF_NSAPI_DEFAULT_WIFI_SSID))
#error [NOT_SUPPORTED] No network configuration found for this target.
#endif
#ifndef MBED_CONF_APP_ECHO_SERVER_ADDR
#error [NOT_SUPPORTED] Requires parameters from mbed_app.json
#endif

#include "mbed.h"
#include "greentea-client/test_env.h"
#include "unity/unity.h"
#include "utest.h"
#include "utest/utest_stack_trace.h"
#include "multihoming_tests.h"

using namespace utest::v1;

namespace {
NetworkInterface *net;
WiFiInterface *wifi;
}

char interface_name[MBED_CONF_MULTIHOMING_INTERFACES_NUM][INTERFACE_NAME_LEN];

#if MBED_CONF_NSAPI_SOCKET_STATS_ENABLE
mbed_stats_socket_t udp_stats[MBED_CONF_NSAPI_SOCKET_STATS_MAX_COUNT];
#endif

NetworkInterface *get_interface()
{
    return net;
}



const char *sec2str(nsapi_security_t sec)
{
    switch (sec) {
        case NSAPI_SECURITY_NONE:
            return "None";
        case NSAPI_SECURITY_WEP:
            return "WEP";
        case NSAPI_SECURITY_WPA:
            return "WPA";
        case NSAPI_SECURITY_WPA2:
            return "WPA2";
        case NSAPI_SECURITY_WPA_WPA2:
            return "WPA/WPA2";
        case NSAPI_SECURITY_UNKNOWN:
        default:
            return "Unknown";
    }
}


int scan_demo(WiFiInterface *wifi)
{
    WiFiAccessPoint *ap;

    printf("Scan:\n");

    int count = wifi->scan(NULL, 0);

    if (count <= 0) {
        printf("scan() failed with return value: %d\n", count);
        return 0;
    }

    //Limit number of network arbitrary to 15
    count = count < 15 ? count : 15;

    ap = new WiFiAccessPoint[count];
    count = wifi->scan(ap, count);

    if (count <= 0) {
        printf("scan() failed with return value: %d\n", count);
        return 0;
    }

    for (int i = 0; i < count; i++) {
        printf("Network: %s secured: %s BSSID: %hhX:%hhX:%hhX:%hhx:%hhx:%hhx RSSI: %hhd Ch: %hhd\n", ap[i].get_ssid(),
               sec2str(ap[i].get_security()), ap[i].get_bssid()[0], ap[i].get_bssid()[1], ap[i].get_bssid()[2],
               ap[i].get_bssid()[3], ap[i].get_bssid()[4], ap[i].get_bssid()[5], ap[i].get_rssi(), ap[i].get_channel());
    }
    printf("%d networks available.\n", count);

    delete[] ap;
    return count;
}

static void _ifup()
{
    net = NetworkInterface::get_default_instance();
    nsapi_error_t err = net->connect();
    net->get_interface_name(interface_name[0]);
    TEST_ASSERT_EQUAL(NSAPI_ERROR_OK, err);
    printf("MBED: UDPClient IP address is '%s' interface name %s\n", net->get_ip_address(), interface_name[0]);

    wifi = WiFiInterface::get_default_instance();

    if (wifi) {
        int count = 0;
        count = scan_demo(wifi);

        if (count == 0) {
            printf("No WIFI APNs found - can't continue further.\n");
            return;
        }

        printf("\nConnecting to %s...\n", MBED_CONF_APP_WIFI_SSID);
        int ret = wifi->connect(MBED_CONF_APP_WIFI_SSID, MBED_CONF_APP_WIFI_PASSWORD, NSAPI_SECURITY_WPA_WPA2);
        if (ret != 0) {
            printf("\nConnection error: %d\n", ret);
            return;
        }
        wifi->get_interface_name(interface_name[1]);
        printf("MAC: %s\n", wifi->get_mac_address());
        printf("IP: %s\n", wifi->get_ip_address());
        printf("Netmask: %s\n", wifi->get_netmask());
        printf("Gateway: %s\n", wifi->get_gateway());
        printf("RSSI: %d\n\n", wifi->get_rssi());
        printf("Wifi interface name: %s\n\n", interface_name[1]);

    } else {
        printf("ERROR: No WiFiInterface found.\n");
    }

}

static void _ifdown()
{
    net->disconnect();
    wifi->disconnect();
    printf("MBED: ifdown\n");
}

void drop_bad_packets(UDPSocket &sock, int orig_timeout)
{
    nsapi_error_t err;
    sock.set_timeout(0);
    while (true) {
        err = sock.recvfrom(NULL, 0, 0);
        if (err == NSAPI_ERROR_WOULD_BLOCK) {
            break;
        }
    }
    sock.set_timeout(orig_timeout);
}

void fill_tx_buffer_ascii(char *buff, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        buff[i] = (rand() % 43) + '0';
    }
}

#if MBED_CONF_NSAPI_SOCKET_STATS_ENABLE
int fetch_stats()
{
    return SocketStats::mbed_stats_socket_get_each(&udp_stats[0], MBED_CONF_NSAPI_SOCKET_STATS_MAX_COUNT);
}
#endif

// Test setup
utest::v1::status_t greentea_setup(const size_t number_of_cases)
{
    GREENTEA_SETUP(480, "default_auto");
    _ifup();
    return greentea_test_setup_handler(number_of_cases);
}

void greentea_teardown(const size_t passed, const size_t failed, const failure_t failure)
{
    _ifdown();
    return greentea_test_teardown_handler(passed, failed, failure);
}

Case cases[] = {
    Case("MULTIHOMING_SYNCHRONOUS_DNS", MULTIHOMING_SYNCHRONOUS_DNS),
    Case("MULTIHOMING_ASYNCHRONOUS_DNS", MULTIHOMING_ASYNCHRONOUS_DNS),
    Case("MULTIHOMING_UDPSOCKET_ECHOTEST", MULTIHOMING_UDPSOCKET_ECHOTEST),
    Case("MULTIHOMING_UDPSOCKET_ECHOTEST_NONBLOCK", MULTIHOMING_UDPSOCKET_ECHOTEST_NONBLOCK),
};

Specification specification(greentea_setup, cases, greentea_teardown, greentea_continue_handlers);

int main()
{
    return !Harness::run(specification);
}
