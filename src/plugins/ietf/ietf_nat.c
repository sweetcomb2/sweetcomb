/*
 * Copyright (c) 2019 PANTHEON.tech.
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

#include <sys_util.h>
#include "sc_plugins.h"

#include <vom/om.hpp>
#include <vom/prefix.hpp>
#include <vom/types.hpp>
#include <vom/nat_static.hpp>
#include <vom/nat_static_cmds.hpp>
#include <vom/nat_binding.hpp>
#include <vom/nat_binding_cmds.hpp>

#include <string>
#include <exception>

using namespace boost;
using namespace std;
using namespace VOM;

#define MODULE_NAME "ietf-nat-client"

enum mapping_type {
    STATIC = 0,
    DYNAMIC_IMPLICIT,
    DYNAMIC_EXPLICIT,
    UNKNOWN,
};

struct nat_interface_t {
    bool inbound_nat44;
    bool inbound_nat64;
    bool inbound_nat66;
    bool outbound_nat44;
    bool outbound_nat64;
    bool outbound_nat66;
};

/**
 * @brief Wrapper struct for VOM address range
 */
struct address_range_t {
    int vrf_id;
    string first_ip;
    string last_ip;
};

static sr_error_t nat_external_ip_address_add_del(address_range_t *address_rng, bool is_add)
{
    sr_error_t rc = SR_ERR_OK;

    SRP_LOG_ERR("External ip range : %s -> %s", address_rng->first_ip.c_str(), address_rng->last_ip.c_str());
/*
    //     char tmp_ip1[VPP_IP4_ADDRESS_STRING_LEN];
    //     char tmp_ip2[VPP_IP4_ADDRESS_STRING_LEN];

    ARG_CHECK(SR_ERR_INVAL_ARG, address_r);

    //if end of IP range not provided, then range size = 1 with only first ip
    if (!address_r->last_ip_address_set) {
        memcpy(&address_r->payload.last_ip_address[0],
               &address_r->payload.first_ip_address[0],
               VPP_IP4_ADDRESS_LEN);
    }

    if (hardntohlu32(address_r->payload.last_ip_address) <
        hardntohlu32(address_r->payload.first_ip_address)) {
        SRP_LOG_ERR_MSG("End address less than start address");
        return SR_ERR_INVAL_ARG;
    }

    //     strncpy(tmp_ip1, sc_ntoa(address_r->payload.first_ip_address),
    //             VPP_IP4_ADDRESS_STRING_LEN);
    //     strncpy(tmp_ip2, sc_ntoa(address_r->payload.last_ip_address),
    //             VPP_IP4_ADDRESS_STRING_LEN);
    //     SRP_LOG_DBG("Fist ip address: %s, last ip address: %s, twice_nat: %u,"
    //                 "is_add: %u", tmp_ip1, tmp_ip2, address_r->payload.twice_nat,
    //                 address_r->payload.is_add);

    int rv = nat44_add_del_addr_range(&address_r->payload);
    if (0 != rv) {
        SRP_LOG_ERR_MSG("Failed set address range.");
        rc = SR_ERR_OPERATION_FAILED;
    }
*/
    return rc;
}

static inline int get_network_broadcast_address(string *ip_broadcast,
    const string ip_prefix,
    uint8_t prefix_length)
{
    uint8_t mask = ~0;
    uint8_t prefix = prefix_length;
    vector<string> ip_address;
    const char* delim = ".";

    if (32 < prefix_length) {
        SRP_LOG_ERR_MSG("Prefix length to big.");
        return -1;
    }

    char *token = strtok(const_cast<char*>(ip_prefix.c_str()), delim);
    while (token != nullptr)
    {
        ip_address.push_back(string(token));
        token = strtok(nullptr, delim);
	}

    for (vector<string>::iterator it = ip_address.begin(); it != ip_address.end();) {
        uint8_t ip = (uint8_t)stoi(*it);
        ip_broadcast->append(
                    to_string( ip  | (mask >> (prefix > 8 ? 8 : prefix))));
        if ((++it) != ip_address.end()) {
            ip_broadcast->append(".");
            if (prefix >= 8) {
                prefix -= 8;
            } else {
                prefix = 0;
            }
        }
    }
    return 0;
}

// parse leafs of xpath: /ietf-nat:nat/instances/instance[id='%s']/policy[id='%s']/external-ip-address-pool[pool-id='%s']/
static int parse_policy_entry(
    const sr_val_t *val, address_range_t *address_range)
{
    int rc;
    char tmp_str[VPP_IP4_PREFIX_STRING_LEN] = {0};
    uint8_t prefix_len = 0;

    ARG_CHECK2(SR_ERR_INVAL_ARG, val, address_range);

    if(sr_xpath_node_name_eq(val->xpath, "external-ip-pool")) {
        rc = prefix2ip4(tmp_str, val->data.string_val, &prefix_len);
        if (0 != rc) {
            SRP_LOG_ERR_MSG("Error translate");
            return SR_ERR_INVAL_ARG;
        }
        address_range->first_ip = string(tmp_str);
        if (prefix_len < VPP_IP4_HOST_PREFIX_LEN) {
            get_network_broadcast_address(&address_range->last_ip, 
                                          address_range->first_ip.c_str(),
                                          prefix_len);
        }
    }
    return SR_ERR_OK;
}

// XPATH: /ietf-nat:nat/instances/instance[id='%s']/policy[id='%s']/external-ip-address-pool[pool-id='%s']/
static int nat_policy_config_cb(
    sr_session_ctx_t *ds, const char *xpath, sr_notif_event_t event,
    void *private_ctx)
{
    UNUSED(private_ctx);
    sr_change_iter_t *it;
    sr_change_oper_t oper;
    sr_val_t *old_val, *new_val;
    sr_xpath_ctx_t state = {0};
    int rc = SR_ERR_OK;
    address_range_t new_address_rng = {0};
    address_range_t old_address_rng = {0};
    string policy_id, pool_id;
    bool create = false;
    bool del = false;
    int curr_item_idx, item_idx = -1;

   ARG_CHECK2(SR_ERR_INVAL_ARG, ds, xpath);

    if (event == SR_EV_VERIFY)
        return SR_ERR_OK;

    SRP_LOG_INF("In %s", __FUNCTION__);

    rc = sr_get_changes_iter(ds, (char *)xpath, &it);
    if (rc != SR_ERR_OK) {
        sr_free_change_iter(it);
        return rc;
    }

    foreach_change(ds, it, oper, old_val, new_val) {
        SRP_LOG_DBG("A change detected in '%s', op=%d",
                    new_val ? new_val->xpath : old_val->xpath, oper);

        policy_id = sr_xpath_key_value(new_val ? new_val->xpath :
                                                 old_val->xpath,
                                "policy", "id", &state);
        sr_xpath_recover(&state);

        if (sr_xpath_node_name_eq(xpath, "external-ip-address-pool")) {
            pool_id = sr_xpath_key_value(new_val ? new_val->xpath : old_val->xpath,
                      "external-ip-address-pool", "pool-id", &state);

            curr_item_idx = stoi(pool_id);
            if (curr_item_idx != item_idx)
            {
                if (item_idx > -1) {
                    if (del)
                        rc = nat_external_ip_address_add_del(&old_address_rng, false);
                    if (create)
                        rc = nat_external_ip_address_add_del(&new_address_rng, true);
                }

                item_idx = curr_item_idx;
                create = false;
                del = false;
                new_address_rng = { 0 };
                old_address_rng = { 0 };
            }
        }                                
        sr_xpath_recover(&state);

        new_address_rng.vrf_id = ~0;
        old_address_rng.vrf_id = ~0;
        try {
            switch (oper) {
                case SR_OP_CREATED:
                    create = true;
                    parse_policy_entry(new_val, &new_address_rng);
                    break;
                case SR_OP_DELETED:
                    del = true;
                    parse_policy_entry(old_val, &old_address_rng);
                    break;
                default:
                    SRP_LOG_WRN_MSG("Operation not supported");
                    continue;
                }
        } catch (std::exception &exc) {
            SRP_LOG_ERR("Error: %s", exc.what());
        }
        sr_free_val(old_val);
        sr_free_val(new_val);
    }
    if (del)
        rc = nat_external_ip_address_add_del(&old_address_rng, false);
    if (create)
        rc = nat_external_ip_address_add_del(&new_address_rng, true);

error:
    sr_free_change_iter(it);
    return rc;
}

/**
 * @brief Wrapper struct for VOM nat static mapping
 */
struct static_mapping_t {
    enum mapping_type mtype;
    bool is_ipv6;
    int protocol;
    int local_port;
    int external_port;
    string local_ip;
    string external_ip;
    int instance_id;
    int index;
};

inline string make_uuid(static_mapping_t *mapping) {
    return MODULE_NAME + string("-") +
            to_string(mapping->instance_id) + string("-") +
            to_string(mapping->index);
}

int nat_static_mapping(static_mapping_t *mapping)
{
    if (!mapping->local_ip.empty() && !mapping->external_ip.empty()) {
        if (STATIC == mapping->mtype) {
            try {
                const string uuid = make_uuid(mapping);
                OM::mark_n_sweep ms(uuid);

                boost::asio::ip::address in_addr = boost::asio::ip::address::from_string(mapping->local_ip);
                boost::asio::ip::address out_addr = boost::asio::ip::address::from_string(mapping->external_ip);

                nat_static ns(in_addr, out_addr);
                OM::write(uuid, ns);
                SRP_LOG_DBG("(OM::write(%s)) : add static mapping %s => %s", uuid.c_str(),
                            in_addr.to_string().c_str(), 
                            out_addr.to_string().c_str());
            } catch (std::exception &exc) {
                // catch boost exception from prefix_t
                SRP_LOG_ERR("Error: %s", exc.what());
                return SR_ERR_OPERATION_FAILED;
            }
        }
    }
    return SR_ERR_OK;
}

// parse leafs of xpath: /ietf-nat:nat/instances/instance[id='%s']/mapping-table/mapping-entry[index='%s']/
static int parse_mapping_entry(
    const sr_val_t *val,
    static_mapping_t *mapping)
{
    int rc;
    char tmp_str[VPP_IP4_PREFIX_STRING_LEN] = {0};

    ARG_CHECK2(SR_ERR_INVAL_ARG, val, mapping);

    sr_xpath_ctx_t state = {0};

    if(sr_xpath_node_name_eq(val->xpath, "type")) {
        if (!strncmp("static", val->data.string_val, strlen("static"))) {
            mapping->mtype = STATIC;
        } else if (!strncmp("dynamic-implicit", val->data.string_val,
            strlen("dynamic-implicit"))) {
            mapping->mtype = DYNAMIC_IMPLICIT;
        } else if (!strncmp("dynamic-explicit", val->data.string_val,
            strlen("dynamic-explicit"))) {
                mapping->mtype = DYNAMIC_EXPLICIT;
        }
    } else if(sr_xpath_node_name_eq(val->xpath, "transport-protocol")) {
        if (SR_UINT8_T != val->type) {
            SRP_LOG_ERR("Wrong transport-protocol, type, current type: %d.",
                        val->type);
            return SR_ERR_INVAL_ARG;
        }
        mapping->protocol = val->data.uint8_val;
    } else if(sr_xpath_node_name_eq(val->xpath, "internal-src-address")) {
        if (SR_STRING_T != val->type) {
            SRP_LOG_ERR("Wrong internal-src-address, type, current type: %d.",
                        val->type);
            return SR_ERR_INVAL_ARG;
        }
        rc = prefix2ip4(tmp_str, val->data.string_val, NULL);
        if (0 != rc) {
            SRP_LOG_ERR_MSG("Error translate");
            return SR_ERR_INVAL_ARG;
        }
        mapping->local_ip = string(tmp_str);
    } else if(sr_xpath_node_name_eq(val->xpath, "external-src-address")) {
        if (SR_STRING_T != val->type) {
            SRP_LOG_ERR("Wrong external-src-address, type, current type: %d.",
                        val->type);
            return SR_ERR_INVAL_ARG;
        }
        rc = prefix2ip4(tmp_str, val->data.string_val, NULL);
        if (0 != rc) {
            SRP_LOG_ERR_MSG("Error translate");
            return SR_ERR_INVAL_ARG;
        }
        mapping->external_ip = string(tmp_str);
    } else if (sr_xpath_node(val->xpath, "internal-src-port", &state)) {
        sr_xpath_recover(&state);
        if(sr_xpath_node_name_eq(val->xpath, "start-port-number")) {
            mapping->local_port = val->data.uint16_val;
        }
    } else if (sr_xpath_node(val->xpath, "external-src-port", &state)) {
        sr_xpath_recover(&state);
        if(sr_xpath_node_name_eq(val->xpath, "start-port-number")) {
            mapping->external_port = val->data.uint16_val;
        }
    }
    return SR_ERR_OK;
}

// XPATH: /ietf-nat:nat/instances/instance[id='%s']/mapping-table/mapping-entry[index='%s']/
static int nat_mapping_table_config_cb(
    sr_session_ctx_t *ds, const char *xpath, sr_notif_event_t event,
    void *private_ctx)
{
    UNUSED(private_ctx);
    sr_change_iter_t *it;
    sr_change_oper_t oper;
    sr_val_t *old_val, *new_val;
    sr_xpath_ctx_t state = {0};
    int rc = SR_ERR_OK;
    static_mapping_t new_mapping = { STATIC, 0, };
    string instance_id, mapping_table_index;
    bool create = false;
    int curr_item_idx, item_idx = -1;

    ARG_CHECK2(SR_ERR_INVAL_ARG, ds, xpath);

    if (event == SR_EV_VERIFY)
        return SR_ERR_OK;

    if (!sr_xpath_node_name_eq(xpath, "mapping-entry"))
        return SR_ERR_OK;

    SRP_LOG_INF("In %s", __FUNCTION__);

    rc = sr_get_changes_iter(ds, (char *)xpath, &it);
    if (rc != SR_ERR_OK) {
        sr_free_change_iter(it);
        return rc;
    }

    foreach_change(ds, it, oper, old_val, new_val) {
        // TODO: connection-limits => continue

        SRP_LOG_DBG("A change detected in '%s', op=%d",
                    new_val ? new_val->xpath : old_val->xpath, oper);
        instance_id = sr_xpath_key_value(new_val ? new_val->xpath :
                                                   old_val->xpath,
                                    "instance", "id", &state);
        sr_xpath_recover(&state);
        if (sr_xpath_node_name_eq(xpath, "mapping-entry")) {
            mapping_table_index = sr_xpath_key_value(new_val ? new_val->xpath :
                                                               old_val->xpath,
                                    "mapping-entry", "index", &state);

            curr_item_idx = stoi(mapping_table_index);
            if (curr_item_idx != item_idx)
            {
                if (item_idx > -1 && create) {
                    new_mapping.instance_id = stoi(instance_id);
                    new_mapping.index = item_idx;
                    rc = nat_static_mapping(&new_mapping);
                }

                item_idx = curr_item_idx;
                create = false;
                new_mapping = { STATIC, 0, };
            }
        }
        sr_xpath_recover(&state);

        try {
            switch (oper) {
                case SR_OP_CREATED:
                    create = true;
                    parse_mapping_entry(new_val, &new_mapping);
                    break;
                case SR_OP_DELETED:
                    break;
                default:
                    SRP_LOG_WRN_MSG("Operation not supported");
                    break;
                }
        } catch (std::exception &exc) {
            SRP_LOG_ERR("Error: %s", exc.what());
        }
        sr_free_val(old_val);
        sr_free_val(new_val);
    }

    if (create) {
        new_mapping.instance_id = stoi(instance_id);
        new_mapping.index = item_idx;
        rc = nat_static_mapping(&new_mapping);    
    }

error:
    sr_free_change_iter(it);
    return rc;
}

static int
nat44_interface_add_del(const string &if_name, 
    const nat_interface_t &nat_interface, bool is_add)
{
    const string uuid = MODULE_NAME + if_name;
    OM::mark_n_sweep ms(uuid);

    try {
        SRP_LOG_DBG("Inft '%s' nat44 inbound (%s), outbound(%s)",
                    if_name.c_str(),
                    nat_interface.inbound_nat44?"true":"false",
                    nat_interface.outbound_nat44?"true":"false");

        std::shared_ptr<interface> intf = nullptr;
        if (!if_name.empty()) {
            intf = interface::find(if_name);
            if (nullptr == intf) {
                SRP_LOG_ERR_MSG("Interfaces does not exist");
                return SR_ERR_OPERATION_FAILED;
            }
        }

        SRP_LOG_DBG("Inft handle : %s",intf->handle().to_string().c_str());
        if (is_add) {
            if (nat_interface.inbound_nat44) {
                nat_binding nb_in(*intf, direction_t::INPUT, l3_proto_t::IPV4,
                                  nat_binding::zone_t::INSIDE);
                OM::write(uuid, nb_in);
            }
            if (nat_interface.outbound_nat44) {
                nat_binding nb_out(*intf, direction_t::OUTPUT, l3_proto_t::IPV4,
                                   nat_binding::zone_t::OUTSIDE);
                OM::write(uuid, nb_out);
            }
        }
    } catch (std::exception &exc) {
        // catch boost exception from prefix_t
        SRP_LOG_ERR("Error: %s", exc.what());
        return SR_ERR_OPERATION_FAILED;
    }
    return SR_ERR_OK;
}

// XPATH: /ietf-interfaces/interfaces/interface[name='%s']/if-nat:nat
static int nat_interface_config_cb(
    sr_session_ctx_t *ds, const char *xpath, sr_notif_event_t event,
    void *private_ctx)
{
    UNUSED(private_ctx);
    sr_change_iter_t *it;
    sr_change_oper_t oper;
    sr_val_t *old_val, *new_val, *tmp;
    sr_xpath_ctx_t state = {0};
    int rc = SR_ERR_OK;
    bool create = false;
    bool del = false;
    string if_name;
    nat_interface_t nat_interface = {0};

    ARG_CHECK2(SR_ERR_INVAL_ARG, ds, xpath);

    if (event == SR_EV_VERIFY)
        return SR_ERR_OK;

    SRP_LOG_INF("In %s", __FUNCTION__);

    rc = sr_get_changes_iter(ds, (char *)xpath, &it);
    if (rc != SR_ERR_OK) {
        sr_free_change_iter(it);
        return rc;
    }

    foreach_change(ds, it, oper, old_val, new_val) {
        switch (oper) {
            case SR_OP_CREATED:
                create = true;
                tmp = new_val;
                break;
            case SR_OP_DELETED:
                del = true;
                tmp = old_val;
                break;
            default:
                SRP_LOG_WRN_MSG("Operation not supported");
                continue;
        }

        if_name = sr_xpath_key_value(tmp->xpath, "interface", "name", &state);
        sr_xpath_recover(&state);

        if (sr_xpath_node(tmp->xpath, "inbound", &state)) {
            sr_xpath_recover(&state);
            if (sr_xpath_node_name_eq(tmp->xpath, "nat44-support")) {
                nat_interface.inbound_nat44 = tmp->data.bool_val;
            } else if (sr_xpath_node_name_eq(tmp->xpath, "nat64-support")) {
                nat_interface.inbound_nat64 = tmp->data.bool_val;
            } else if (sr_xpath_node_name_eq(tmp->xpath, "nat66-support")) {
                nat_interface.inbound_nat66 = tmp->data.bool_val;
            }
        } else if (sr_xpath_node(tmp->xpath, "outbound", &state)) {
            sr_xpath_recover(&state);
            if (sr_xpath_node_name_eq(tmp->xpath, "nat44-support")) {
                nat_interface.outbound_nat44 = tmp->data.bool_val;
            } else if (sr_xpath_node_name_eq(tmp->xpath, "nat64-support")) {
                nat_interface.outbound_nat64 = tmp->data.bool_val;
            } else if (sr_xpath_node_name_eq(tmp->xpath, "nat66-support")) {
                nat_interface.outbound_nat66 = tmp->data.bool_val;
            }
        }
    }

    if (del)
        rc = nat44_interface_add_del(if_name, nat_interface, false);
    if (create)
        rc = nat44_interface_add_del(if_name, nat_interface, true);

error:
    sr_free_change_iter(it);
    return rc;
}

int
ietf_nat_init(sc_plugin_main_t *pm)
{
    int rc = SR_ERR_OK;
    SRP_LOG_DBG_MSG("Initializing ietf-nat plugin.");

    rc = sr_subtree_change_subscribe(pm->session, "/ietf-nat:nat/instances/instance/policy/external-ip-address-pool",
            nat_policy_config_cb, NULL, 90, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (rc != SR_ERR_OK) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/ietf-nat:nat/instances/instance/connection-limits",
            nat_mapping_table_config_cb, NULL, 91, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (rc != SR_ERR_OK) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/ietf-nat:nat/instances/instance/mapping-table/mapping-entry",
            nat_mapping_table_config_cb, NULL, 100, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (rc != SR_ERR_OK) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/ietf-interfaces:interfaces/interface/interface-nat:nat",
            nat_interface_config_cb, NULL, 92, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (rc != SR_ERR_OK) {
        goto error;
    }

    SRP_LOG_DBG_MSG("ietf-nat plugin initialized successfully.");
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("Error by initialization of ietf-nat plugin. Error : %d", rc);
    return rc;
}

void
ietf_nat_exit(__attribute__((unused)) sc_plugin_main_t *pm)
{
}

SC_INIT_FUNCTION(ietf_nat_init);
SC_EXIT_FUNCTION(ietf_nat_exit);
