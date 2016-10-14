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

#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>

#include <boost/property_tree/ini_parser.hpp>

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <functional>
#include <ctime>
#include <fstream>
#include <cctype>

#if defined(__APPLE__) || defined(LINUX) || defined(linux)
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#endif

#include "easy_drcom_exception.hpp"

struct easy_drcom_config {
    struct config_general {
        int mode;
        std::string username;
        std::string password;
        bool auto_online;
        bool auto_redial;
    } general;
    
    struct config_remote {
        std::string ip;
        uint32_t port;
        
        bool use_broadcast;
        std::vector<uint8_t> mac;
    } remote;
    
    struct config_local {
        std::string nic;
        std::string hostname;
        std::string kernel_version;
        
        std::string ip;
        std::vector<uint8_t> mac;
        
        uint32_t eap_timeout;
        uint32_t udp_timeout;
    } local;
    
    struct config_fake {
        bool enable;
        std::vector<uint8_t> mac;
        std::string username;
        std::string password;
    } fake;
} conf;

// Log Config
#define EASYDRCOM_DEBUG
//#define EASYDRCOM_PRINT_DBG_ON_SCREEN
#include "log.hpp"

#define MAX_RETRY_TIME 2
#include "utils.hpp"
#include "drcom_dealer.hpp"
#include "eap_dealer.hpp"

#define MAJOR_VERSION "v0.9"

#if defined (WIN32)
#define VERSION (MAJOR_VERSION " for Windows")
#elif defined __APPLE__
#define VERSION (MAJOR_VERSION " for Mac OSX")
#elif defined (OPENWRT)
#define VERSION (MAJOR_VERSION " for OpenWrt (mips AR7xxx/9xxx)")
#elif defined (LINUX)
#define VERSION (MAJOR_VERSION " for Linux")
#endif

int read_config(std::string path)
{
    boost::property_tree::ptree pt;
    try {
        boost::property_tree::ini_parser::read_ini(path, pt);
        conf.general.mode = pt.get<int>("General.Mode");
        conf.general.username = pt.get<std::string>("General.UserName");
        conf.general.password = pt.get<std::string>("General.PassWord");
        conf.local.nic = pt.get<std::string>("Local.NIC");
    }
    catch (std::exception& e) {
        SYS_LOG_ERR("Failed to read '" << path << "' - " << e.what() << std::endl);
        return EBADF;
    }
    
    conf.general.auto_online = pt.get("General.AutoOnline", true);
    conf.general.auto_redial = pt.get("General.AutoRedial", true);
    
    conf.remote.ip = pt.get("Remote.IP", "172.25.8.4");
    conf.remote.port = pt.get("Remote.Port", 61440);
    conf.remote.use_broadcast = pt.get("Remote.UseBroadcast", true);
    
    if (!conf.remote.use_broadcast)
        conf.remote.mac = str_mac_to_vec(pt.get("Remote.MAC", "00:1a:a9:c3:3a:59"));
    
    conf.local.hostname = pt.get("Local.HostName", "EasyDrcom for HITwh");
    conf.local.kernel_version = pt.get("Local.KernelVersion", VERSION);
    
    conf.local.eap_timeout = pt.get("Local.EAPTimeout", 1000);
    conf.local.udp_timeout = pt.get("Local.UDPTimeout", 2000);
    
    conf.fake.enable = pt.get("Fake.Enable", 0);
    
    SYS_LOG_DBG("General.UserName = " << conf.general.username << ", General.PassWord = " << conf.general.password << ", General.Mode = " << conf.general.mode << std::endl);
    SYS_LOG_DBG("General.AutoOnline = " << (conf.general.auto_online ? "True" : "False") << ", General.AutoRedial = " << (conf.general.auto_redial ? "True" : "False" ) << std::endl);
    SYS_LOG_DBG("Remote.IP:Port = " << conf.remote.ip << ":" << conf.remote.port << ", Remote.UseBroadcast = " << (conf.remote.use_broadcast ? "True" : "False" ) << std::endl);
    if (!conf.remote.use_broadcast) SYS_LOG_DBG("Remote.MAC = " << hex_to_str(&conf.remote.mac[0], 6, ':') << std::endl);
    SYS_LOG_DBG("Local.NIC = " << conf.local.nic << ", Local.HostName = " << conf.local.hostname << ", Local.KernelVersion = " << conf.local.kernel_version << std::endl);
    SYS_LOG_DBG("Local.EAPTimeout = " << conf.local.eap_timeout << ", Local.UDPTimeout = " << conf.local.udp_timeout << std::endl);
    
    try {
        conf.local.ip = get_ip_address(conf.local.nic);
        conf.local.mac = get_mac_address(conf.local.nic);
        
        SYS_LOG_INFO("Fetch NIC IP & MAC successfully." << std::endl);
        SYS_LOG_INFO("Local.IP = " << conf.local.ip << ", Local.MAC = " << hex_to_str(&conf.local.mac[0], 6, ':') << std::endl);
    }
    catch (std::exception& e) {
        SYS_LOG_ERR("Failed to fetch NIC info - " << e.what() << std::endl);
        return EBADF;
    }
    
    if (conf.fake.enable) // fake user
    {
        try {
            conf.fake.mac = str_mac_to_vec(pt.get<std::string>("Fake.MAC"));
            conf.fake.username = pt.get<std::string>("Fake.UserName");
            conf.fake.password = pt.get<std::string>("Fake.PassWord");
        }
        catch (std::exception& e) {
            SYS_LOG_ERR("Failed to read fake settings - " << e.what() << std::endl);
            return EBADF;
        }
        
        SYS_LOG_INFO("Fetch fake settings successfully." << std::endl);
        SYS_LOG_INFO("Fake.MAC = " << hex_to_str(&conf.fake.mac[0], 6, ':') << ", Fake.UserName = " << conf.fake.username << ", Fake.PassWord = " << conf.fake.password << std::endl);
        
    }
    SYS_LOG_INFO("Loaded config successfully." << std::endl);
    
    return 0;
}

std::shared_ptr<eap_dealer> eap;
std::shared_ptr<drcom_dealer_base> drcom;

enum ONLINE_STATE
{
    OFFLINE_PROCESSING,
    OFFLINE_NOTIFY,
    OFFLINE,
    ONLINE_PROCESSING,
    ONLINE,
};
ONLINE_STATE state = OFFLINE;

std::mutex mtx;
std::condition_variable cv;

std::vector<uint8_t> broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
std::vector<uint8_t> nearest_mac = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };

void online_func()
{
    do
    {
        try
        {
            do
            {
                state = ONLINE_PROCESSING;
				try
                {
                    if (conf.general.mode != 1) // 宿舍区认证模式
                    {
                        if (conf.remote.use_broadcast)
                        {
                            eap->logoff(nearest_mac);
                            eap->logoff(nearest_mac);
                            
                            if (eap->start(broadcast_mac)) break;
                            if (eap->response_identity(broadcast_mac)) break;
                            if (eap->response_md5_challenge(broadcast_mac)) break;
                        }
                        else
                        {
                            eap->logoff(conf.remote.mac);
                            eap->logoff(conf.remote.mac);
                            
                            if (eap->start(conf.remote.mac)) break;
                            if (eap->response_identity(conf.remote.mac)) break;
                            if (eap->response_md5_challenge(conf.remote.mac)) break;
                        }
                    }
                    
                    if (conf.general.mode <= 1) // U31.R0
                    {
                        std::shared_ptr<drcom_dealer_u31> dealer = std::dynamic_pointer_cast<drcom_dealer_u31>(drcom);
                        
                        if (dealer->start_request()) break;
                        if (dealer->send_login_auth()) break;
                    }
                    else // U62.R0
                    {
                        std::shared_ptr<drcom_dealer_u62> dealer = std::dynamic_pointer_cast<drcom_dealer_u62>(drcom);
                    }
                    
                    while (true && state != OFFLINE_PROCESSING) // Keep Alive
                    {
                        try
                        {
                            if (conf.general.mode <= 1) // U31.R0
                            {
                                std::shared_ptr<drcom_dealer_u31> dealer = std::dynamic_pointer_cast<drcom_dealer_u31>(drcom);
                                
                                if (dealer->send_alive_request()) break;
                                if (dealer->send_alive_pkt1()) break;
                                if (dealer->send_alive_pkt2()) break;
                            }
                            else // U62.R0
                            {
                                std::shared_ptr<drcom_dealer_u62> dealer = std::dynamic_pointer_cast<drcom_dealer_u62>(drcom);
                            
                                if (dealer->send_alive_pkt1()) break;
                                if (dealer->send_alive_pkt2()) break;
                            }
                            
                            state = ONLINE;
                            
                            std::unique_lock<std::mutex> lock(mtx);
                            cv.wait_for(lock, std::chrono::seconds(20));
                        }
                        catch (std::exception& e)
                        {
                            state = OFFLINE;
                            SYS_LOG_ERR("Keep Alive: " << e.what() << std::endl);
                            break;
                        }
                    }
                }
				catch (std::exception& e)
                {
                    state = OFFLINE;
                    SYS_LOG_ERR("Go Online: " << e.what() << std::endl);
                    break;
                }
                
                if (state != OFFLINE_PROCESSING)
                    state = OFFLINE;
            }
            while (false); // run once
            
            if (state != OFFLINE_PROCESSING)
            {
                SYS_LOG_INFO("Connection broken, try to redial after 5 seconds." << std::endl);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
        catch (std::exception& e)
        {
            SYS_LOG_ERR("Thread Online: " << e.what() << std::endl);
        }
    } while (conf.general.auto_redial && state != OFFLINE_PROCESSING); // auto redial
    
    std::unique_lock<std::mutex> lock(mtx);
    state = OFFLINE_NOTIFY;
    cv.notify_one();
}

void offline_func()
{
    try
    {
        state = OFFLINE_PROCESSING;
        
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_one();
        
        while (state != OFFLINE_NOTIFY)
            cv.wait(lock); // wait for signal
        
        if (conf.general.mode <= 1) // U31.R0
        {
            std::shared_ptr<drcom_dealer_u31> dealer = std::dynamic_pointer_cast<drcom_dealer_u31>(drcom);
            
            dealer->send_alive_request();
            dealer->start_request();
            dealer->send_logout_auth();
        }
        // U62.R0 needn't do anything
    }
    catch (std::exception& e)
    {
        SYS_LOG_ERR("Go Offline: " << e.what() << std::endl);
    }
    
    if (conf.general.mode == 0 || conf.general.mode == 2) // 宿舍区
    {
        if (conf.remote.use_broadcast)
        {
            eap->logoff(broadcast_mac);
            eap->logoff(nearest_mac);
        }
        else
        {
            eap->logoff(conf.remote.mac);
        }
    }

    state = OFFLINE;
    SYS_LOG_INFO("Offline." << std::endl);
}

int main(int argc, const char * argv[])
{
    int ret = 0;
    bool background = false, redirect_to_null = false;
    std::string config_path = "EasyDrcom.conf";
    auto clog_def = std::clog.rdbuf();
    auto cout_def = std::cout.rdbuf();
    auto cerr_def = std::cerr.rdbuf();
#ifdef OPENWRT
    std::string log_path = "/tmp/EasyDrcom.log";
#else
    std::string log_path = "EasyDrcom.log";
#endif
    
    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-b"))
            background = true;
        else if (!strcmp(argv[i], "-r"))
            redirect_to_null = true;
        else if (!strcmp(argv[i], "-c"))
        {
            if (i + 1 < argc)
                config_path = argv[i+1];
        }
        else if (!strcmp(argv[i], "-o"))
        {
            if (i + 1 < argc)
                log_path = argv[i+1];
        }
    }
    
    std::ofstream log(log_path);
    if (!log.is_open())
    {
        std::cerr << "[Error] Failed to open log '" << log_path << "', quitting..." << std::endl;
        return ENOENT;
    }
    std::clog.rdbuf(log.rdbuf());
    
    std::ofstream null("/dev/null");
    if (redirect_to_null)
    {
        std::cout.rdbuf(null.rdbuf());
        std::cerr.rdbuf(null.rdbuf());
    }
    
    SYS_LOG_INFO("EasyDrcom " << VERSION << " (build on " << __DATE__ << " " << __TIME__ << ")" << std::endl);
    SYS_LOG_INFO("Code by Shindo, Contributors: mylight, SwimmingTiger." << std::endl << std::endl);
    SYS_LOG_INFO("Initializing..." << std::endl);
    SYS_LOG_INFO("Loading config from '" << config_path << "'..." << std::endl);
    
    // Initialization
    if ((ret = read_config(config_path)) != 0)
        goto end;
    
    
#if defined(WIN32)
	WSADATA	wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    
    try
    {
        eap = std::shared_ptr<eap_dealer>(new eap_dealer(conf.local.nic, conf.local.mac, conf.local.ip, conf.general.username, conf.general.password)); // the fucking "Segmentation fault", so we must have to use this line all the time!!!
        
        if (!conf.fake.enable)
        {
            if (conf.general.mode <= 1) // U31.R0
                drcom = std::shared_ptr<drcom_dealer_base>(new drcom_dealer_u31(conf.local.mac, conf.local.ip, conf.general.username, conf.general.password, conf.remote.ip, conf.remote.port, conf.local.hostname, conf.local.kernel_version));
            else // U62.R0
                drcom = std::shared_ptr<drcom_dealer_base>(new drcom_dealer_u62(conf.local.mac, conf.local.ip, conf.general.username, conf.general.password, conf.remote.ip, conf.remote.port, conf.local.hostname, conf.local.kernel_version));
        }
        else
        {
            if (conf.general.mode <= 1) // U31.R0
                drcom = std::shared_ptr<drcom_dealer_base>(new drcom_dealer_u31(conf.fake.mac, conf.local.ip, conf.fake.username, conf.fake.password, conf.remote.ip, conf.remote.port, conf.local.hostname, conf.local.kernel_version));
            else // U62.R0
                drcom = std::shared_ptr<drcom_dealer_base>(new drcom_dealer_u62(conf.fake.mac, conf.local.ip, conf.fake.username, conf.fake.password, conf.remote.ip, conf.remote.port, conf.local.hostname, conf.local.kernel_version));
        }
    }
    catch (std::exception& e)
    {
        SYS_LOG_ERR(e.what() << std::endl);
        ret = ENETRESET;
        goto end;
    }
    
    SYS_LOG_INFO("Initialization done!" << std::endl);
    
    if (background)
    {
        SYS_LOG_INFO("Start in background, turn on Auto Online & Auto Redial." << std::endl);
        conf.general.auto_online = true;
        conf.general.auto_redial = true;
    }
    
    if (!background)
        SYS_LOG_INFO("Enter 'help' to get help." << std::endl);
    
    if (!conf.general.auto_online)
    {
        SYS_LOG_INFO("Enter 'online' to go online!" << std::endl);
    }
    else
    {
        SYS_LOG_INFO("Going online..." << std::endl);
        std::thread(online_func).detach();
    }
    
    if (background)
    {
        std::thread(online_func).join();
    }
    else
    {
        // Command Loop
        std::string cmd;
        while (true)
        {
            std::cin >> cmd;
            if (!cmd.compare("online"))
            {
                if (state == ONLINE)
                {
                    SYS_LOG_INFO("Already online!" << std::endl);
                }
                else if (state == ONLINE_PROCESSING)
                {
                    SYS_LOG_INFO("Online Processing!" << std::endl);
                }
                else if (state == OFFLINE_PROCESSING || state == OFFLINE_NOTIFY)
                {
                    SYS_LOG_INFO("Offline Processing!" << std::endl);
                }
                else if (state == OFFLINE)
                {
                    SYS_LOG_INFO("Going online..." << std::endl);
                    std::thread(online_func).detach();
                }
            }
            else if (!cmd.compare("offline"))
            {
                if (state == OFFLINE)
                {
                    SYS_LOG_INFO("Haven't been online!" << std::endl);
                }
                else if (state == ONLINE_PROCESSING)
                {
                    SYS_LOG_INFO("Online Processing!" << std::endl);
                }
                else if (state == OFFLINE_PROCESSING)
                {
                    SYS_LOG_INFO("Offline Processing!" << std::endl);
                }
                else if (state == ONLINE)
                {
                    SYS_LOG_INFO("Going offline..." << std::endl);
                    std::thread(offline_func).detach();
                }
            }
            else if (!cmd.compare("quit"))
            {
                if (state == ONLINE_PROCESSING)
                {
                    SYS_LOG_INFO("Please wait for online processing finished." << std::endl);
                    continue;
                }
                
                if (state == OFFLINE_PROCESSING)
                {
                    SYS_LOG_INFO("Please wait for offline processing finished." << std::endl);
                    continue;
                }
                
                if (state == ONLINE)
                {
                    SYS_LOG_INFO("Going offline..." << std::endl);
                    offline_func();
                }
                
                SYS_LOG_INFO("Quitting..." << std::endl);
                std::cout << "[EasyDrcom Info] Bye Bye!" << std::endl;
                break;
            }
            else if (!cmd.compare("help"))
            {
                SYS_LOG_INFO("EasyDrcom " << VERSION << " (build on " << __DATE__ << " " << __TIME__ << ")" << std::endl);
                SYS_LOG_INFO("Code by Shindo, Contributors: mylight, SwimmingTiger." << std::endl << std::endl);
                SYS_LOG_INFO("Command list:" << std::endl);
                SYS_LOG_INFO("online - go online." << std::endl);
                SYS_LOG_INFO("offline - go offline." << std::endl);
                SYS_LOG_INFO("quit - quit EasyDrcom." << std::endl);
            }
            else
            {
                SYS_LOG_INFO("Wrong command: " << cmd << std::endl);
            }
        }
    }
    
end:
    std::cout.rdbuf(cout_def);
    std::cerr.rdbuf(cerr_def);
    std::clog.rdbuf(clog_def);
    
    log.close();
    null.close();
    
#if defined (WIN32)
	WSACleanup();
#endif
    return ret;
}
