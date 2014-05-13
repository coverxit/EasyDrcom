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

#ifndef __INCLUDE_EASYDRCOMEXCEPTION__
#define __INCLUDE_EASYDRCOMEXCEPTION__

class easy_drcom_exception : public std::exception
{
public:
	easy_drcom_exception(const std::string& message) : message(message) { }
    easy_drcom_exception(const std::string& message, int err) {
        std::stringstream stream;
        stream << message << ", errno = " << err << ", desc: " << strerror(err);
        this->message = stream.str();
    }
	const char* what() const throw() { return message.c_str(); }
    
    ~easy_drcom_exception() throw() {}

private:
	std::string message;
};

#endif // __INCLUDE_EASYDRCOMEXCEPTION__