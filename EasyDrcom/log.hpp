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

#ifndef __INCLUDE_LOG__
#define __INCLUDE_LOG__

std::string log_now()
{
    time_t now = time(NULL);
    auto tm = localtime(&now);
    
    char buf[128];
    sprintf(buf, "%4d-%02d-%02d %02d:%02d:%02d", 1900 + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    
    std::string str(buf);
    return str;
}

#define LOG {                                                        \
    std::stringstream for_log_use_stream;                            \
    for_log_use_stream

#define PRINT_INFO                                                   \
    std::clog << log_now() << " " << for_log_use_stream.str() << std::flush;\
    std::cout << for_log_use_stream.str();
#define PRINT_ERR                                                    \
    std::clog << log_now() << " " << for_log_use_stream.str() << std::flush;\
    std::cerr << for_log_use_stream.str();
#ifdef EASYDRCOM_PRINT_DBG_ON_SCREEN
    #define PRINT_DBG                                                \
        std::clog << log_now() << " " << for_log_use_stream.str() << std::flush;\
        std::cout << for_log_use_stream.str();
#else
    #define PRINT_DBG                                                \
        std::clog << log_now() << " " << for_log_use_stream.str() << std::flush;
#endif

#define LOG_INFO(section, info)                                      \
    LOG << "[" << section << " Info] " << info; PRINT_INFO }
#define LOG_ERR(section, err)                                        \
    LOG << "[" << section << " Error] " << err; PRINT_ERR }
#ifdef EASYDRCOM_DEBUG
    #define LOG_DBG(section, db)                                     \
        LOG << "[" << section << " Debug] " << db; PRINT_DBG }
#else
    #define LOG_DBG(db)
#endif

#ifdef EASYDRCOM_DEBUG
    #define U31_LOG_INFO(info)       LOG_INFO("U31", info)
    #define U31_LOG_ERR(err)         LOG_ERR("U31", err)
    #define U31_LOG_DBG(db)          LOG_DBG("U31", db)

    #define U62_LOG_INFO(info)       LOG_INFO("U62", info)
    #define U62_LOG_ERR(err)         LOG_ERR("U62", err)
    #define U62_LOG_DBG(db)          LOG_DBG("U62", db)

    #define EAP_LOG_INFO(info)  LOG_INFO("EAP", info)
    #define EAP_LOG_ERR(err)    LOG_ERR("EAP", err)
    #define EAP_LOG_DBG(db)     LOG_DBG("EAP", db)

    #define SYS_LOG_INFO(info)  LOG_INFO("EasyDrcom", info)
    #define SYS_LOG_ERR(err)    LOG_ERR("EasyDrcom", err)
    #define SYS_LOG_DBG(db)     LOG_DBG("EasyDrcom", db)

    #define SVR_LOG_ERR(err)    LOG_INFO("EAP", err)
#else
    #define U31_LOG_INFO(info)       
    #define U31_LOG_ERR(err)         
    #define U31_LOG_DBG(db)          

    #define U62_LOG_INFO(info)       
    #define U62_LOG_ERR(err)         
    #define U62_LOG_DBG(db)          

    #define EAP_LOG_INFO(info)  
    #define EAP_LOG_ERR(err)    
    #define EAP_LOG_DBG(db)     

    #define SYS_LOG_INFO(info)  LOG_INFO("EasyDrcom", info)
    #define SYS_LOG_ERR(err)    LOG_ERR("EasyDrcom", err)
    #define SYS_LOG_DBG(db)     

    #define SVR_LOG_ERR(err)    LOG_ERR("Server",err)
#endif

#endif // __INCLUDE_LOG__
