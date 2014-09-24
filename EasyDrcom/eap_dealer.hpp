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

#ifndef __INCLUDE_EAP_DEALER__
#define __INCLUDE_EAP_DEALER__

#include <pcap.h>

#define DRCOM_EAP_FRAME_SIZE    (0x60)
#define EAP_MD5_VALUE_SIZE      (0x10)

#define EAP_AUTO_RETRY(step) EAP_AUTO_RETRY_EX(step, pkt_data, handler_success, handler_error)

#define EAP_AUTO_RETRY_EX(step, data, success, error)                                                       \
    {                                                                                                       \
        int retry_times = 0, ret;                                                                           \
        try {                                                                                               \
            while ((ret = pcap.send(data, success, error)) < 0 && retry_times < MAX_RETRY_TIME)             \
            {                                                                                               \
                retry_times++;                                                                              \
                EAP_LOG_ERR("Failed to perform " << step << ", retry times = " << retry_times << std::endl);\
                EAP_LOG_INFO("Try to perform " << step << " after 2 seconds." << std::endl);                \
                std::this_thread::sleep_for(std::chrono::seconds(2));                                       \
            }                                                                                               \
            if (retry_times == MAX_RETRY_TIME)                                                              \
            {                                                                                               \
                EAP_LOG_ERR("Failed to perfrom " << step << ", stopped." << std::endl);                     \
                return -1;                                                                                  \
            }                                                                                               \
        } catch (std::exception &e) {                                                                       \
            EAP_LOG_ERR(step << ": " << e.what() << std::endl);                                             \
        }                                                                                                   \
        return ret;                                                                                         \
    }

#define EAP_HANDLE_ERROR(step)                                                                          \
    auto handler_error = [&](std::string error) {                                                       \
        EAP_LOG_ERR(step << ": " << error << std::endl)                                                 \
    };

#define EAP_SHOW_PACKET_TYPE(step)                                                                      \
    EAP_LOG_DBG("Recevied after " << step << ", "                                                       \
                 << "eapol_type = 0x" << std::hex << (int) eap_header->eapol_type                       \
                 << ", eap_id = 0x" << std::hex << (int) eap_header->eap_id                             \
                 << ", eap_type = 0x" << std::hex << (int) eap_header->eap_type                         \
                 << ", eap_length = " << (int) eap_header->eap_length << std::endl);

#if defined (WIN32)
#define ETHER_ADDR_LEN          6       /* length of an Ethernet address */
#define ETHERNET_HEADER_SIZE    14      /* length of two Ethernet address plus ether type*/
struct ether_header
{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};
#endif

struct eap_header
{
    uint8_t eapol_version;
    uint8_t eapol_type; // 0x01 - Start, 0x02 - Logoff, 0x00 - EAP Packet
    uint16_t eapol_length; // equal to eap_length
    uint8_t eap_code;
    uint8_t eap_id;
    uint16_t eap_length;
    uint8_t eap_type;
    uint8_t eap_md5_value_size;
    uint8_t eap_md5_value[16];
};

class pcap_dealer
{
public:
    pcap_dealer(std::string nic, std::vector<uint8_t> mac)
    {
        const int               SNAP_LEN = 1518;
        char                    errbuf[PCAP_ERRBUF_SIZE] = {0};
        char                    filter[100];
        struct bpf_program      fp;
        
        if (NULL == (handle = pcap_open_live(nic.c_str(), SNAP_LEN, 1, conf.local.eap_timeout, errbuf)))
            throw easy_drcom_exception("pcap_open_live: " + std::string(errbuf));
        
        if (pcap_datalink(handle) != DLT_EN10MB)
            throw easy_drcom_exception("pcap_datalink: not an Ethernet device.");
        
        sprintf(filter, "ether dst %02x:%02x:%02x:%02x:%02x:%02x and ether proto 0x888e",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        
        if (pcap_compile(handle, &fp, filter, 0, 0) == -1)
            throw easy_drcom_exception(std::string("pcap_compile: ") + pcap_geterr(handle));
        
        if (pcap_setfilter(handle, &fp) == -1)
            throw easy_drcom_exception(std::string("pcap_setfilter: ") + pcap_geterr(handle));
        
        pcap_freecode(&fp);
    }
    
    ~pcap_dealer()
    {
        pcap_close(handle);
    }
    
    int send(std::vector<uint8_t> data, std::function<int(std::vector<uint8_t>)> success, std::function<void(std::string)> error = nullptr)
    {
        try
        {
            if (pcap_sendpacket(handle, &data[0], (int) data.size()) != 0)
                throw easy_drcom_exception("pcap_sendpacket: " + std::string(pcap_geterr(handle)));
            
            struct pcap_pkthdr *header;
            const uint8_t *pkt_data;
            int ret = pcap_next_ex(handle, &header, &pkt_data);
            std::vector<uint8_t> recv;
            
            switch (ret)
            {
                case 0: // Timeout
                    throw easy_drcom_exception("pcap_next_ex: timeout.");
                    
                case 1: // Success
                    recv.resize(header->len);
                    memcpy(&recv[0], pkt_data, header->len);
                    return success(recv);

                default:
                    throw easy_drcom_exception(std::string("pcap_next_ex: ") + pcap_geterr(handle));
            }
        }
        catch (std::exception& e)
        {
            if (error != nullptr)
                error(e.what());
            
            return -1;
        }
    }
    
private:
    pcap_t *handle;
    std::thread thread_loop;
};

class eap_dealer
{
public:
    eap_dealer(std::string nic, std::vector<uint8_t> local_mac, std::string local_ip, std::string identity, std::string key) : key(str_to_vec(key)), // the local_ip can be used to detect 'IP conflict!'
        local_mac(local_mac), pcap(nic, local_mac)
    {
        auto ip = str_ip_to_vec(local_ip);
        
        resp_id = str_to_vec(identity);
        resp_id.insert(resp_id.end(), { 0x00, 0x44, 0x61, 0x00, 0x00 });
        resp_id.insert(resp_id.end(), ip.begin(), ip.end());
        
        resp_md5_id = str_to_vec(identity);
        resp_md5_id.insert(resp_md5_id.end(), { 0x00, 0x44, 0x61, 0x0a, 0x00 });
        resp_md5_id.insert(resp_md5_id.end(), ip.begin(), ip.end());
    }
    
    int start(std::vector<uint8_t> gateway_mac)
    {
        EAP_LOG_INFO("Start." << std::endl);
        
        std::vector<uint8_t> pkt_data(DRCOM_EAP_FRAME_SIZE, 0);
        
        uint8_t eapol_start[] = {
            0x01,             // Version: 802.1X-2001
            0x01,             // Type: Start
            0x00, 0x00        // Length: 0
        };
        
        struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
        
        memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
        memcpy(&pkt_data[sizeof(eth_header)], eapol_start, 4);
        
        auto handler_success = [&](std::vector<uint8_t> recv) -> int {
            struct ether_header *eth_header;
            struct eap_header *eap_header;
            
            eth_header = (struct ether_header*) &recv[0];
            eap_header = (struct eap_header*) (&recv[0] + sizeof(struct ether_header));
            
            EAP_SHOW_PACKET_TYPE("Start");
            
            if (eap_header->eapol_type != 0x00) // EAP Packet
                return -1;
            
                                        // EAP Request                  // EAP Failure
            if (eap_header->eap_code != 0x01 /*&& eap_header->eap_code != 0x04*/)
                return -1;
            
            // We don't retry at this time when failure occurs.
            /*if (eap_header->eap_code == 0x04) // Failure
            {
                EAP_LOG_INFO("Failure, send Start again." << std::endl);
                
                // Typically because abnormal exit last time
                // So send a logoff packet and then retry
                
                logoff(gateway_mac);
                return start(gateway_mac);
            }*/
            
            // Now, only eap_code = 0x01 packets, select eap_type = 0x01 packet
            if (eap_header->eap_type != 0x01) // Request, Identity
                return -1;
            
            EAP_LOG_INFO("Gateway returns: Request, Identity" << std::endl);
            resp_eap_id = eap_header->eap_id;
            
            return 0;
        };
        
        EAP_HANDLE_ERROR("Start");
        EAP_AUTO_RETRY("Start");
    }
    
    int logoff(std::vector<uint8_t> gateway_mac) // this a function typically returns success
    {
        EAP_LOG_INFO("Logoff." << std::endl);
        
        std::vector<uint8_t> pkt_data(DRCOM_EAP_FRAME_SIZE, 0);
        
        uint8_t eapol_logoff[] = {
            0x01,             // Version: 802.1X-2001
            0x02,             // Type: Logoff
            0x00, 0x00        // Length: 0
        };
        
        struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
        memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
        memcpy(&pkt_data[sizeof(eth_header)], eapol_logoff, 4);
        
        auto handler_success = [&](std::vector<uint8_t> recv) -> int {
            struct ether_header *eth_header;
            struct eap_header *eap_header;
            
            eth_header = (struct ether_header*) &recv[0];
            eap_header = (struct eap_header*) (&recv[0] + sizeof(struct ether_header));
            
            EAP_SHOW_PACKET_TYPE("Logoff");
            
            // We needn't to deal with the packet back
            return 0;
        };
        
        auto handler_error = [&](std::string) {
            // We needn't to deal with the packet back
        };
        
        try
        {
            pcap.send(pkt_data, handler_success, handler_error);
        }
        catch (std::exception &e)
        {
            EAP_LOG_ERR("Logoff :" << e.what() << std::endl);
        }
        return 0;
    }
    
    int response_identity(std::vector<uint8_t> gateway_mac)
    {
        EAP_LOG_INFO("Response, Identity." << std::endl);
        
        std::vector<uint8_t> pkt_data(DRCOM_EAP_FRAME_SIZE, 0);
        
        std::vector<uint8_t> eap_resp_id = {
            0x01,           // Version: 802.1X-2001
            0x00,           // Type: EAP Packet
            0x00, 0x00,     // EAP Length
            0x02,           // Code: Reponse
            (uint8_t) resp_eap_id,    // Id
            0x00, 0x00,     // EAP Length
            0x01            // Type: Identity
        };
        
        uint16_t eap_length = htons(5 + resp_id.size());
        
        memcpy(&eap_resp_id[2], &eap_length, 2);
        memcpy(&eap_resp_id[6], &eap_length, 2);
        
        struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
        
        memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
        memcpy(&pkt_data[sizeof(eth_header)], &eap_resp_id[0], eap_resp_id.size());
        
        memcpy(&pkt_data[sizeof(eth_header) + eap_resp_id.size()], &resp_id[0], resp_id.size());
        
        auto handler_success = [&](std::vector<uint8_t> recv) -> int {
            struct ether_header *eth_header;
            struct eap_header *eap_header;
            
            eth_header = (struct ether_header*) &recv[0];
            eap_header = (struct eap_header*) (&recv[0] + sizeof(struct ether_header));
            
            EAP_SHOW_PACKET_TYPE("Response, Identity");
            
            if (eap_header->eapol_type != 0x00) // EAP Packet
                return -1;
            
                                        // EAP Request                  // Request, MD5-Challenge EAP
            if (eap_header->eap_code != 0x01 && eap_header->eap_type != 0x04)
                return -1;
            
            EAP_LOG_INFO("Gateway returns: Request, MD5-Challenge EAP" << std::endl);
            resp_md5_eap_id = eap_header->eap_id;
            resp_md5_attach_key = std::vector<uint8_t>(eap_header->eap_md5_value, eap_header->eap_md5_value + EAP_MD5_VALUE_SIZE);
            
            return 0;
        };
        
        EAP_HANDLE_ERROR("Response, Identity");
        EAP_AUTO_RETRY("Response, Identity");
    }
    
    int response_md5_challenge(std::vector<uint8_t> gateway_mac)
    {
        EAP_LOG_INFO("Response, MD5-Challenge EAP." << std::endl);
        
        std::vector<uint8_t> pkt_data(DRCOM_EAP_FRAME_SIZE, 0);
        
        std::vector<uint8_t> eap_resp_md5_ch = {
            0x01,               // Version: 802.1X-2001
            0x00,               // Type: EAP Packet
            0x00, 0x00,         // EAP Length
            0x02,               // Code: Reponse
            (uint8_t) resp_md5_eap_id,    // Id
            0x00, 0x00,         // EAP Length
            0x04,               // Type: MD5-Challenge EAP
            EAP_MD5_VALUE_SIZE  // EAP-MD5 Value-Size = 16
        };
        
        uint16_t eap_length = htons(6 + EAP_MD5_VALUE_SIZE + resp_md5_id.size());
        
        memcpy(&eap_resp_md5_ch[2], &eap_length, 2);
        memcpy(&eap_resp_md5_ch[6], &eap_length, 2);
        
        struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
        
        memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
        memcpy(&pkt_data[sizeof(eth_header)], &eap_resp_md5_ch[0], eap_resp_md5_ch.size());
        
        std::vector<uint8_t> eap_key(1 +                                // EAP Id
                                     key.size() + EAP_MD5_VALUE_SIZE);
        eap_key[0] = resp_md5_eap_id;
        memcpy(&eap_key[1], &key[0], key.size());
        memcpy(&eap_key[1 + key.size()], &resp_md5_attach_key[0], EAP_MD5_VALUE_SIZE);
        
        std::vector<uint8_t> md5_value = get_md5_digest(eap_key);
        memcpy(&pkt_data[sizeof(eth_header) + eap_resp_md5_ch.size()], &md5_value[0], md5_value.size());
        
        memcpy(&pkt_data[sizeof(eth_header) + eap_resp_md5_ch.size() + EAP_MD5_VALUE_SIZE], &resp_md5_id[0], resp_md5_id.size());
        
        auto handler_success = [&](std::vector<uint8_t> recv) -> int {
            struct ether_header *eth_header;
            struct eap_header *eap_header;
            
            eth_header = (struct ether_header*) &recv[0];
            eap_header = (struct eap_header*) (&recv[0] + sizeof(struct ether_header));
            
            EAP_SHOW_PACKET_TYPE("Response, MD5-Challenge EAP");
            
            if (eap_header->eapol_type != 0x00) // EAP Packet
                return -1;
            
                                        // Request                      // Success
            if (eap_header->eap_code != 0x01 && eap_header->eap_code != 0x03)
                return -1;
            
            if (eap_header->eap_code == 0x01) // Request
            {
                if (eap_header->eap_type != 0x02) // Notification
                    return -1;
                
                std::string noti(ntohs(eap_header->eap_length) - 5, 0); // 1 for NULL Terminator
                memcpy(&noti[0], ((uint8_t*)eap_header + 4 + 5), // 4 - EAPol Header, 5 - EAP Header
                       ntohs(eap_header->eap_length) - 5);
                
                EAP_LOG_INFO("Gateway returns: Request, Notification: " << noti << std::endl);
                
                if (!noti.compare("userid error1"))
                    EAP_LOG_INFO("Tips: Account or password authentication fails, the system does not exist in this account." << std::endl);
                
                if (!noti.compare("userid error3"))
                    EAP_LOG_INFO("Tips: Account or password authentication fails, the system does not exist in this account or your account has arrears down." << std::endl);
                
                logoff(gateway_mac); // Need to send a logoff, or the gateway will always send notification
                
                return 1; // Don't retry when notification
            }
            
            // In fact, this condition is always true
            if (eap_header->eap_code == 0x03) // Success
                EAP_LOG_INFO("Gateway returns: Success" << std::endl);
            
            return 0;
        };
        
        EAP_HANDLE_ERROR("Response, MD5-Challenge EAP");
        EAP_AUTO_RETRY("Response, MD5-Challenge EAP");
    }
    
    struct ether_header get_eth_header(std::vector<uint8_t> gateway_mac, std::vector<uint8_t> local_mac)
    {
        struct ether_header eth_header;
        
        memcpy(eth_header.ether_dhost, &gateway_mac[0], 6);
        memcpy(eth_header.ether_shost, &local_mac[0], 6);
        eth_header.ether_type = htons(0x888e); // 802.1X Authentication (0x888e)
        
        return eth_header;
    }
    
private:
    pcap_dealer pcap;
    
    // Const
    std::vector<uint8_t> local_mac;
    std::vector<uint8_t> resp_id, resp_md5_id, key;

    // Recved from Request, Identity
    int resp_eap_id;
    
    // Recved from Request, MD5-Challenge EAP
    int resp_md5_eap_id;
    std::vector<uint8_t> resp_md5_attach_key;
};
#endif // __INCLUDE_EAP_DEALER__
