/**
 * Copyright (C) 2014 Shindo
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

#ifndef __INCLUDE__UDP_DEALER__
#define __INCLUDE__UDP_DEALER__

#if defined(__APPLE__) || defined(__MACH__) || defined(LINUX) || defined(linux)
#include <fcntl.h>
#endif

#if defined(__APPLE__) || defined(__MACH__)
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif
#endif

#if defined(LINUX) || defined(linux)
#include <sys/select.h>
#endif

const size_t buffer_size = 2048;

class udp_dealer
{
public:
    udp_dealer(std::string gateway_ip, uint32_t gateway_port, std::string local_ip)
    {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
            throw easy_drcom_exception("socket", errno);
        
#if defined (WIN32)
		u_long mode = 1;
		ioctlsocket(sock, FIONBIO, &mode);
#else
        auto flag = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flag | O_NONBLOCK);
#endif
        
        struct sockaddr_in local;
        local.sin_family = AF_INET;
        local.sin_port = 0; // system defined
        local.sin_addr.s_addr = inet_addr(local_ip.c_str());
        
        if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0)
            throw easy_drcom_exception("bind", errno);
        
        gateway.sin_family = AF_INET;
        gateway.sin_port = htons(gateway_port);
        gateway.sin_addr.s_addr = inet_addr(gateway_ip.c_str());
    }
    
    int post(std::vector<uint8_t>& data, std::function<int(std::vector<uint8_t>)> success, std::function<void(std::string)> error = nullptr)
    {
        try
        {
            int total = 0;
            int left = (int) data.size();
            while (total < data.size())
            {
#if defined (WIN32)
				int len = (int) sendto(sock, (const char*) &data[0], data.size(), NULL, (struct sockaddr *)&gateway, sizeof(gateway));
#else
                int len = (int) sendto(sock, &data[0], data.size(), MSG_NOSIGNAL, (struct sockaddr *)&gateway, sizeof(gateway));
#endif
                if (len < 0)
                {
                    if (errno == EWOULDBLOCK && left > 0)
                        continue;
                    else
                        throw easy_drcom_exception("sendto", errno);
                }
                
                total += len;
                left -= len;
            }
            
            int ret = wait_socket();
            if (ret < 0)
                throw easy_drcom_exception("select", errno);
            if (ret == 0)
                throw easy_drcom_exception("select: timeout");
            
            std::vector<uint8_t> recv;
            while (true)
            {
                std::vector<uint8_t> buf(buffer_size, 0);
                int len = (int) ::recv(sock, (char*) &buf[0], buffer_size, 0);
                
                if (len <= 0)
                    break; // connection closed
                
                buf.resize(len);
                recv.insert(recv.end(), buf.begin(), buf.end());
                
                if (len < buffer_size)
                    break;
            }
            
            return success(recv);
        }
        catch (std::exception& e)
        {
            if (error != nullptr)
                error(e.what());
                
            return -1;
        }
    }
    
private:
    int wait_socket()
    {
        fd_set fds;
        struct timeval tv;
        
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        
        tv.tv_usec = 0;
        tv.tv_sec = conf.local.udp_timeout / 1000;
        
        return select(sock + 1, &fds, NULL, NULL, &tv);
    }
    
private:
    int sock;
    struct sockaddr_in gateway;
};

#define U31_AUTO_RETRY(step) U31_AUTO_RETRY_EX(step, pkt_data, handler_success, handler_error)

#define U31_AUTO_RETRY_EX(step, data, success, error)                                                   \
{                                                                                                       \
    int retry_times = 0, ret;                                                                           \
    try {                                                                                               \
        while ((ret = udp.post(data, success, error)) < 0 && retry_times < MAX_RETRY_TIME)              \
        {                                                                                               \
            retry_times++;                                                                              \
            U31_LOG_ERR("Failed to perform " << step << ", retry times = " << retry_times << std::endl);\
            U31_LOG_INFO("Try to perform " << step << " after 2 seconds." << std::endl);                \
            std::this_thread::sleep_for(std::chrono::seconds(2));                                       \
        }                                                                                               \
        if (retry_times == MAX_RETRY_TIME)                                                              \
        {                                                                                               \
            U31_LOG_ERR("Failed to perfrom " << step << ", stopped." << std::endl);                     \
            return -1;                                                                                  \
        }                                                                                               \
    } catch (std::exception &e) {                                                                       \
        U31_LOG_ERR(step << ": " << e.what() << std::endl);                                             \
    }                                                                                                   \
    return ret;                                                                                         \
}

#define U31_HANDLE_ERROR(step)                                                                      \
    auto handler_error = [&](std::string error) {                                                   \
        U31_LOG_ERR(step << ": " << error << std::endl)                                             \
    };

#define U31_LOG_RECV_DUMP(step)                                                                     \
{                                                                                                   \
    U31_LOG_DBG("Received after " << step << ", dump:" << std::endl);                                \
    hexdump(recv);                                                                                  \
}

#define U31_LOG_SEND_DUMP                                                                           \
{                                                                                                   \
    U31_LOG_DBG("send packet data dump:" << std::endl);                                             \
    hexdump(pkt_data);                                                                              \
}

#define U62_AUTO_RETRY(step) U62_AUTO_RETRY_EX(step, pkt_data, handler_success, handler_error)

#define U62_AUTO_RETRY_EX(step, data, success, error)                                                   \
{                                                                                                       \
    int retry_times = 0, ret;                                                                           \
    try {                                                                                               \
        while ((ret = udp.post(data, success, error)) < 0 && retry_times < MAX_RETRY_TIME)              \
        {                                                                                               \
            retry_times++;                                                                              \
            U62_LOG_ERR("Failed to perform " << step << ", retry times = " << retry_times << std::endl);\
            U62_LOG_INFO("Try to perform " << step << " after 2 seconds." << std::endl);                \
            std::this_thread::sleep_for(std::chrono::seconds(2));                                       \
        }                                                                                               \
        if (retry_times == MAX_RETRY_TIME)                                                              \
        {                                                                                               \
            U62_LOG_ERR("Failed to perfrom " << step << ", stopped." << std::endl);                     \
            return -1;                                                                                  \
        }                                                                                               \
    } catch (std::exception &e) {                                                                       \
        U62_LOG_ERR(step << ": " << e.what() << std::endl);                                             \
    }                                                                                                   \
    return ret;                                                                                         \
}

#define U62_HANDLE_ERROR(step)                                                                      \
    auto handler_error = [&](std::string error) {                                                   \
        U62_LOG_ERR(step << ": " << error << std::endl)                                             \
    };

#define U62_LOG_RECV_DUMP(step)                                                                     \
{                                                                                                   \
    U62_LOG_DBG("Received after " << step << ", dump:" << std::endl);                                \
    hexdump(recv);                                                                                  \
}

#define U62_LOG_SEND_DUMP                                                                           \
{                                                                                                   \
    U62_LOG_DBG("send packet data dump:" << std::endl);                                             \
    hexdump(pkt_data);                                                                              \
}

#endif // __INCLUDE__UDP_DEALER__
