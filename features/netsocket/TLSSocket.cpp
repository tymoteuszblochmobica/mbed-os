/*
 * Copyright (c) 2018 ARM Limited
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "TLSSocket.h"

#define TRACE_GROUP "TLSS"
#include "mbed-trace/mbed_trace.h"

// This class requires Mbed TLS SSL/TLS client code
#if defined(MBEDTLS_SSL_CLI_C)

nsapi_error_t TLSSocket::connect(const char *host, uint16_t port, const char *interface_name)
{
    set_hostname(host);

    nsapi_error_t ret = tcp_socket.connect(host, port,interface_name);
    if (ret) {
        return ret;
    }

    return TLSSocketWrapper::do_handshake();
}

TLSSocket::~TLSSocket()
{
    /* Transport is a member of TLSSocket which is derived from TLSSocketWrapper.
     * Make sure that TLSSocketWrapper::close() is called before the transport is
     * destroyed.
     */
    close();
}

#endif // MBEDTLS_SSL_CLI_C