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

#ifndef __INCLUDE_DRCOM_DEALER_U62__
#define __INCLUDE_DRCOM_DEALER_U62__

class drcom_dealer_u62 : public drcom_dealer_base {
private:
    unsigned char version_id[2] = { 0x1F, 0x00 }; //协议版本号（不需要与服务器端一致，程序会自动侦测服务器端版本号）
public:
    drcom_dealer_u62(std::vector<uint8_t> local_mac, std::string local_ip, std::string username, std::string password,
                     std::string gateway_ip, uint32_t gateway_port, std::string hostname, std::string kernel_version
                     ) : local_mac(local_mac), local_ip(str_ip_to_vec(local_ip)),
    hostname(hostname), kernel_version(kernel_version),
    username(username), password(password),
    total_time(0), total_flux(0), balance(0), online_time(0), pkt_id(0), misc1_flux(0), misc3_flux(0),
    udp(gateway_ip, gateway_port, local_ip)
    {}
    
    int send_alive_pkt1(int retry_times = 0)
    {
        U62_LOG_INFO("Send Alive Packet 1." << std::endl);
        
        std::vector<uint8_t> pkt_data;
        pkt_data.push_back(0x07); // Code
        pkt_data.push_back(pkt_id);
        pkt_data.insert(pkt_data.end(), { 0x28, 0x00 }); // Type
        pkt_data.insert(pkt_data.end(), { 0x0B, 0x01 }); // Step
        pkt_data.insert(pkt_data.end(), { version_id[0], version_id[1] }); // 可认为是协议版本号，若和服务器端的不一致则认证失败
        pkt_data.insert(pkt_data.end(), { 0x12, 0x34 }); // 随机码，服务器的响应中会包含同样的内容
        pkt_data.insert(pkt_data.end(), { 0x00, 0x00, 0x00, 0x00 }); // some time
        pkt_data.insert(pkt_data.end(), { 0x00, 0x00 }); // Fixed Unknown
        
        // some flux
        pkt_data.insert(pkt_data.end(), 4, 0x00);
        memcpy(&pkt_data[16], &misc1_flux, 4);
        
        pkt_data.insert(pkt_data.end(), 8, 0x00); // Fixed Unknown, 0x00 *8
        pkt_data.insert(pkt_data.end(), { 0x00, 0x00, 0x00, 0x00 }); // Client IP (Fixed: 0.0.0.0)
        pkt_data.insert(pkt_data.end(), 8, 0x00); // Fixed Unknown, 0x00 *8
        
        U62_LOG_SEND_DUMP
        
        auto handler_success = [&](std::vector<uint8_t> recv) -> int {
            U62_LOG_RECV_DUMP("Alive Packet 1");
            
            if (recv[0] != 0x07) // Misc
                return -1;
            
            if (recv[5] == 0x06) // File
            {
                U62_LOG_INFO("Received 'Misc, File', Send Keep Alive Packet 1 again." << std::endl);

                //复制服务器的协议版本号
                version_id[0] = recv[6];
                version_id[1] = recv[7];
                
                //递归调用太多次会导致程序崩溃，因此加了限制
                if (retry_times < 10) {
                    return send_alive_pkt1(retry_times + 1);
                }
                else {
                    U62_LOG_INFO("Send Too Many Keep Alive Packets!" << std::endl);
                    return -1;
                }
                
            }
            else
            {
                U62_LOG_INFO("Gateway return: Response for Alive Packet 1." << std::endl);
                
                pkt_id++;
                U62_LOG_DBG("next packet id = " << (int) pkt_id << std::endl);
                
                memcpy(&misc3_flux, &recv[16], 4);
                return 0;
            }
        };
        
        U62_HANDLE_ERROR("Send Alive Packet 1");
        U62_AUTO_RETRY("Send Alive Packet 1");
    }
    
    int send_alive_pkt2()
    {
        U62_LOG_INFO("Send Alive Packet 2." << std::endl);
        
        std::vector<uint8_t> pkt_data;
        pkt_data.push_back(0x07); // Code
        pkt_data.push_back(pkt_id);
        pkt_data.insert(pkt_data.end(), { 0x28, 0x00 }); // Type
        pkt_data.insert(pkt_data.end(), { 0x0B, 0x03 }); // Step
        pkt_data.insert(pkt_data.end(), { version_id[0], version_id[1] }); // 可认为是协议版本号，若和服务器端的不一致则认证失败
        pkt_data.insert(pkt_data.end(), { 0x43, 0x21 }); // 随机码，服务器的响应中会包含同样的内容
        pkt_data.insert(pkt_data.end(), { 0x00, 0x00, 0x00, 0x00 }); // some time
        pkt_data.insert(pkt_data.end(), { 0x00, 0x00 }); // Fixed Unknown
        
        // some flux
        pkt_data.insert(pkt_data.end(), 4, 0x00);
        memcpy(&pkt_data[16], &misc3_flux, 4);
        
        pkt_data.insert(pkt_data.end(), 8, 0x00); // Fixed Unknown, 0x00 *8
        pkt_data.insert(pkt_data.end(), local_ip.begin(), local_ip.end()); // Client IP
        pkt_data.insert(pkt_data.end(), 8, 0x00); // Fixed Unknown, 0x00 *8
        
        U62_LOG_SEND_DUMP
        
        auto handler_success = [&](std::vector<uint8_t> recv) -> int {
            U62_LOG_RECV_DUMP("Alive Packet 2");
            
            if (recv[0] != 0x07 && recv[5] != 0x04) // Misc 4
                return -1;
            
            U62_LOG_INFO("Gateway return: Response for Alive Packet 2." << std::endl);
            
            pkt_id++;
            U62_LOG_DBG("next packet id = " << (int) pkt_id << std::endl);
            
            memcpy(&misc1_flux, &recv[16], 4);
            return 0;
        };
        
        U62_HANDLE_ERROR("Send Alive Packet 2");
        U62_AUTO_RETRY("Send Alive Packet 2");
    }
    
private:
    udp_dealer udp;
    
    // Const
    std::vector<uint8_t> local_mac, local_ip;
    std::string username, password, hostname, kernel_version;
    
    // Send Login Auth
    std::vector<uint8_t> challenge;
    
    // Used by Alive
    std::vector<uint8_t> login_md5_a;
    
    // Recv from Success
    std::vector<uint8_t> auth_info;
    
    // Update from Succes & Alive
    uint32_t total_time, total_flux, balance, online_time;
    
    // Send Misc1, 3
    uint8_t pkt_id;
    uint32_t misc1_flux, misc3_flux;
};

#endif
