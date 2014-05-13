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

#if defined(WIN32)
#include <windows.h>
#include <Iphlpapi.h>
#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#elif defined(LINUX) || defined(linux)
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#endif

#if defined(WIN32) || defined(UNDER_CE)
std::vector<uint8_t> get_mac_address(std::string nic)
{
	std::vector<uint8_t> ret(6, 0);
	IP_ADAPTER_INFO AdapterInfo[16]; // Allocate information
	DWORD dwBufLen = sizeof(AdapterInfo); // Save memory size of buffer

	if(GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_SUCCESS)
	{
        bool found = false;
        for (auto ptr = AdapterInfo; ptr != NULL; ptr = ptr->Next)
			if (strstr(nic.c_str(), ptr->AdapterName))
            {
                memcpy(&ret[0], ptr->Address, 6);
                found = true; break;
            }
        
        if (!found)
			throw easy_drcom_exception("get_mac_address: NIC '" + nic + "' not found");
	}
	else 
		throw easy_drcom_exception("get_mac_address: GetAdaptersInfo failed");
    
	return ret;
}
#elif defined(__APPLE__)
std::vector<uint8_t> get_mac_address(std::string nic)
{
    int                     mib[6] = { CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0 };
    size_t                  len;
    char*                   buf;
    uint8_t                 *ptr;
	struct if_msghdr        *ifm;
	struct sockaddr_dl      *sdl;
    std::vector<uint8_t>    ret(6, 0);
    

    if ((mib[5] = if_nametoindex(nic.c_str())) == 0)
        throw easy_drcom_exception("get_mac_address: if_nametoindex failed", errno);
    
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
        throw easy_drcom_exception("get_mac_address: sysctl failed", errno);
    
    buf = new char[len];
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
        throw easy_drcom_exception("get_mac_address: sysctl failed", errno);
    
    ifm = (struct if_msghdr *) buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (uint8_t *) LLADDR(sdl);
    
    memcpy(&ret[0], ptr, 6);
    delete buf;
    return ret;
}
#elif defined(LINUX) || defined(linux)
std::vector<uint8_t> get_mac_address(std::string nic)
{
    int sock;
    struct ifreq dev;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        throw easy_drcom_exception("get_mac_address: socket failed", errno);
    
    strncpy(dev.ifr_name, nic.c_str(), sizeof(dev.ifr_name));
    dev.ifr_name[sizeof(dev.ifr_name)-1] = '\0';
    
    if (ioctl(sock, SIOCGIFHWADDR, &dev) < 0)
        throw easy_drcom_exception("get_mac_address: ioctl failed", errno);
    
    std::vector<uint8_t> ret(6, 0);
    memcpy(&ret[0], dev.ifr_hwaddr.sa_data, 6);
    return ret;
}
#else
    #error "get_mac_address: platform is not supported."
#endif


#if defined(WIN32)
std::string get_ip_address(std::string nic)
{
	std::string ip;

	IP_ADAPTER_INFO AdapterInfo[16]; // Allocate information
	DWORD dwBufLen = sizeof(AdapterInfo); // Save memory size of buffer

	if(GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_SUCCESS)
	{
		bool found = false;
		for (auto ptr = AdapterInfo; ptr != NULL; ptr = ptr->Next)
			if (strstr(nic.c_str(), ptr->AdapterName))
			{
				ip = ptr->IpAddressList.IpAddress.String;
				found = true; break;
			}

		if (!found)
			throw easy_drcom_exception("get_ip_address: NIC '" + nic + "' not found");
	}
	else 
		throw easy_drcom_exception("get_ip_address: GetAdaptersInfo failed");

	return ip;
}
#elif defined(__APPLE__) || defined(LINUX) || defined(linux)
std::string get_ip_address(std::string nic)
{
    struct ifaddrs *ifaddr = NULL;
    std::string ip;
    
    if (getifaddrs(&ifaddr) < 0)
        throw easy_drcom_exception("get_ip_address: getifaddrs failed", errno);
    
    bool found = false;
    for (auto ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (!strcmp(ifa->ifa_name, nic.c_str()))
            if (ifa->ifa_addr->sa_family == AF_INET) // only deal with IPv4
            {
                ip = inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr);
                found = true; break;
            }
    }
    
    if (!found)
        throw easy_drcom_exception("get_ip_address: NIC '" + nic + "' not found.");
    
    return ip;
}
#else
    #error "get_ip_address: platform is not supported."
#endif