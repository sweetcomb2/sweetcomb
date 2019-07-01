/*
 * Copyright (c) 2018 PANTHEON.tech.
 * Copyright (c) 2019 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __SYS_UTIL_H__
#define __SYS_UTIL_H__

//TODO: Add to only one header file
extern "C" {
    #include <sysrepo.h>
    #include <sysrepo/xpath.h>
    #include <sysrepo/plugins.h>
}

#include <iostream>
#include <string>
#include <exception>
#include <boost/asio.hpp>

using namespace std;

/* BEGIN sysrepo utils */

#define foreach_change(ds, it, oper, old, newch) \
    while( (event != SR_EV_ABORT) && \
            sr_get_change_next(ds, it, &oper, &old, &newch) == SR_ERR_OK)

#define XPATH_SIZE 2000
#define NOT_AVAL "NOT AVAILABLE"

#define VPP_IP4_HOST_PREFIX_LEN 32
#define VPP_INTFC_NAME_LEN 64           /* Interface name max length */
#define VPP_IP4_ADDRESS_LEN 4           /* IPv4 length in VPP format */
#define VPP_IP6_ADDRESS_LEN 16          /* IPv6 length in VPP format */
#define VPP_MAC_ADDRESS_LEN 8           /* MAC length in VPP format  */
/* IPv4 and IPv6 length in string format */
#define VPP_IP4_ADDRESS_STRING_LEN INET_ADDRSTRLEN //16, include '\0'
#define VPP_IP6_ADDRESS_STRING_LEN INET6_ADDRSTRLEN //46, include '\0'
#define VPP_IP4_PREFIX_STRING_LEN \
    INET_ADDRSTRLEN + sizeof('/') + 2 // include '\0'
#define VPP_IP6_PREFIX_STRING_LEN \
    INET6_ADDRSTRLEN + sizeof('/') + 3 // include '\0'

/**********************************MACROS**********************************/
#define ARG_CHECK(retval, arg) \
    do \
    { \
        if (NULL == (arg)) \
        { \
            return (retval); \
        } \
    } \
    while (0)

#define ARG_CHECK2(retval, arg1, arg2) \
    ARG_CHECK(retval, arg1); \
    ARG_CHECK(retval, arg2)

#define ARG_CHECK3(retval, arg1, arg2, arg3) \
    ARG_CHECK(retval, arg1); \
    ARG_CHECK(retval, arg2); \
    ARG_CHECK(retval, arg3)

#define ARG_CHECK4(retval, arg1, arg2, arg3, arg4) \
    ARG_CHECK(retval, arg1); \
    ARG_CHECK(retval, arg2); \
    ARG_CHECK(retval, arg3); \
    ARG_CHECK(retval, arg4)

/* Suppress compiler warning about unused variable.
 * This must be used only for callback function else suppress your unused
 * parameter in function prototype. */
#define UNUSED(x) (void)x


static inline int
get_xpath_key(char *dst, char *xpath, char *node, char *key, int length,
              sr_xpath_ctx_t *state) {
    char *tmp;

    tmp = sr_xpath_key_value(xpath, node, key, state);
    if (!tmp) {
        SRP_LOG_ERR("%s %s not found.", node, key);
        return SR_ERR_INVAL_ARG;
    }
    strncpy(dst, tmp, length);
    sr_xpath_recover(state);

    return 0;
}

/* END of sysrepo utils */

namespace utils {

class prefix {
public:
     /* Default Constructor */
    prefix();

    /* Copy constructor */
    prefix(const prefix &p);

    /* Constuctor from string prefix */
    prefix(std::string p);

    /* Create a prefix from a string */
    static prefix make_prefix(std::string p);

    /* Return prefix "AAA.BBB.CCC.DDD/ZZ"
     * "YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY/ZZZ */
    std::string to_string() const;

    /* Extract prefix length "ZZ"/"ZZZ" an IP prefix: "AAA.BBB.CCC.DDD/ZZ"
     * "YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY/ZZZ */
    unsigned short prefix_length() const;

    /* Extract IP "AAA.BBB.CCC.DDD" from an IP prefix: "AAA.BBB.CCC.DDD/ZZ"
     * "YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY/ZZZ */
    boost::asio::ip::address address() const;

    friend ostream& operator<<(ostream& os, const prefix& p);

private:
    boost::asio::ip::address m_address;
    unsigned short m_prefix_len;
};

} //end of utils namespace

#endif /* __SYS_UTIL_H__ */
