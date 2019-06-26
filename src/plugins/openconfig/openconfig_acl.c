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

#include <vom/om.hpp>
#include <vom/interface.hpp>
#include <vom/interface_cmds.hpp>
#include <vom/l3_binding.hpp>
#include <vom/l3_binding_cmds.hpp>
#include "vom/acl_ethertype.hpp"
#include "vom/acl_l2_list.hpp"
#include "vom/acl_l2_rule.hpp"
#include "vom/acl_l3_list.hpp"
#include "vom/acl_l3_rule.hpp"
#include "vom/acl_binding.hpp"

#include <string>
#include <exception>

#include "sc_plugins.h"

using namespace std;
using namespace VOM;
using namespace ACL;

enum acl_type {
    UNKNOWN,
    ACL_RULE,
    MACIP_RULE
};

enum acl_ie_type {
    NONE,
    INGRESS,
    EGRESS
};

/**
 * @brief
 */
typedef struct _acl_rule_t {
    string tag;
    string src_ip4_addr;
    string src_ip6_addr;
    string dst_ip4_addr;
    string dst_ip6_addr;
    uint8_t src_ip4_prefix_len;
    uint8_t dst_ip4_prefix_len;
    uint8_t src_ip6_prefix_len;
    uint8_t dst_ip6_prefix_len;
    route::prefix_t srcIp;
    route::prefix_t dstIp;
    uint8_t src_mac[6];
    uint8_t src_mac_mask[6];
    bool is_permit;
    bool is_ipv6;
    uint8_t protocol;
} acl_rule_t;

typedef struct {
    enum acl_type type;
    string tag;
    l2_list::rules_t l2rules;
    l3_list::rules_t l3rules;
} acl_set_t;

static sr_error_t add_set(acl_set_t &acl_set)
{
    SRP_LOG_INF("In %s", __FUNCTION__);

    try {
        if (!acl_set.l3rules.empty())
        {
            OM::mark_n_sweep ms(acl_set.tag);
            l3_list acl(acl_set.tag, acl_set.l3rules);
            OM::write(acl_set.tag, acl);
        }
    } catch (exception &exc) {
        // catch boost exception from prefix_t
        SRP_LOG_ERR("Error: %s", exc.what());
        return SR_ERR_OPERATION_FAILED;
    }

    return SR_ERR_OK;
}

static sr_error_t add_rule(acl_set_t &acl_set, acl_rule_t &acl_rule)
{
    sr_error_t rc = SR_ERR_OK;

    route::prefix_t srcIp((acl_rule.is_ipv6) ? acl_rule.src_ip6_addr
                                                : acl_rule.src_ip4_addr,
                            (acl_rule.is_ipv6) ? acl_rule.src_ip6_prefix_len
                                                : acl_rule.src_ip4_prefix_len);
    if (acl_set.type == ACL_RULE) {
        route::prefix_t dstIp((acl_rule.is_ipv6) ? acl_rule.dst_ip6_addr
                                                 : acl_rule.dst_ip4_addr,
                              (acl_rule.is_ipv6) ? acl_rule.dst_ip6_prefix_len
                                                 : acl_rule.dst_ip4_prefix_len);
        ACL::l3_rule l3_rule(0,
                             (acl_rule.is_permit)?ACL::action_t::PERMIT
                                                 :ACL::action_t::DENY,
                             srcIp,
                             dstIp,
                             acl_rule.protocol);
        acl_set.l3rules.insert(l3_rule);
    } else {
        VOM::mac_address_t src_mac(acl_rule.src_mac);
        VOM::mac_address_t src_mac_mask(acl_rule.src_mac_mask);

        ACL::l2_rule l2_rule(0,
                             (acl_rule.is_permit)?ACL::action_t::PERMIT
                                                 :ACL::action_t::DENY,
                             srcIp,
                             src_mac,
                             src_mac_mask);
        acl_set.l2rules.insert(l2_rule);
    }

    return SR_ERR_OK;
}
/*
 * @brief Parse leaf from xpath:
 * /openconfig-acl:acl/acl-sets/acl-set[name='%s'][type='%s']'
 * for each acl allocates acl_add_set_t to store its parameters
*/
static int parse_acl_set_entry(
    const sr_val_t *val, acl_set_t &acl_set, acl_rule_t &acl_rule)
{
    sr_xpath_ctx_t state = {0};
    char addr[VPP_IP6_PREFIX_STRING_LEN] = {0};

    if(sr_xpath_node_name_eq(val->xpath, "name")) {
        if (sr_xpath_node(val->xpath, "config", &state)) {
            sr_xpath_recover(&state);
            acl_set.tag = val->data.string_val;
        }
    }
    // parse current acl set - type and sequence-id
    if(sr_xpath_node_name_eq(val->xpath, "type")) {
        if (sr_xpath_node(val->xpath, "config", &state)) {
            sr_xpath_recover(&state);
            if(!strcmp("openconfig-acl:ACL_IPV4", val->data.string_val) ||
            !strcmp("openconfig-acl:ACL_IPV6", val->data.string_val)) {
                acl_set.type = ACL_RULE;
            } else {
                acl_set.type = MACIP_RULE;
            }
        }
    } else if(sr_xpath_node_name_eq(val->xpath, "description")) {
        if (sr_xpath_node(val->xpath, "config", &state)) {
            sr_xpath_recover(&state);
            acl_rule.tag = val->data.string_val;
        }
    }
    if(sr_xpath_node_name_eq(val->xpath, "source-address")) {
        if(sr_xpath_node(val->xpath, "ipv4", &state)) {
            sr_xpath_recover(&state);
            if (0 != prefix2ip4(addr, val->data.string_val,
                                &acl_rule.src_ip4_prefix_len)) {
                SRP_LOG_ERR_MSG("Error translate");
                return SR_ERR_INVAL_ARG;
            }
            acl_rule.is_ipv6 = false;
            acl_rule.src_ip4_addr = addr;
        } else if(sr_xpath_node(val->xpath, "ipv6", &state)) {
            sr_xpath_recover(&state);
            if (0 != prefix2ip6(addr, val->data.string_val,
                                &acl_rule.src_ip6_prefix_len)) {
                SRP_LOG_ERR_MSG("Error translate");
                return SR_ERR_INVAL_ARG;
            }
            acl_rule.is_ipv6 = true;
            acl_rule.src_ip6_addr = addr;
        } else {
            sr_xpath_recover(&state);
            return SR_ERR_INVAL_ARG;
        }
    } else if(sr_xpath_node_name_eq(val->xpath, "destination-address")) {
        if(sr_xpath_node(val->xpath, "ipv4", &state)) {
            sr_xpath_recover(&state);
            if (0 != prefix2ip4(addr, val->data.string_val,
                                &acl_rule.dst_ip4_prefix_len)) {
                SRP_LOG_ERR_MSG("Error translate");
                return SR_ERR_INVAL_ARG;
            }
            acl_rule.is_ipv6 = false;
            acl_rule.dst_ip4_addr = addr;
        } else if(sr_xpath_node(val->xpath, "ipv6", &state)) {
            sr_xpath_recover(&state);
            if (0 != prefix2ip4(addr, val->data.string_val,
                                &acl_rule.dst_ip6_prefix_len)) {
                SRP_LOG_ERR_MSG("Error translate");
                return SR_ERR_INVAL_ARG;
            }
            acl_rule.is_ipv6 = true;
            acl_rule.dst_ip6_addr = addr;
        } else {
            sr_xpath_recover(&state);
            return SR_ERR_INVAL_ARG;
        }
    } else if(sr_xpath_node_name_eq(val->xpath, "source-mac")) {
        int values[6],i;
        if (6 != sscanf(val->data.string_val, "%2x:%2x:%2x:%2x:%2x:%2x%*c",
            &values[0], &values[1], &values[2],
            &values[3], &values[4], &values[5])) {
            SRP_LOG_ERR_MSG("Failed convert string MAC address to int.");
            return SR_ERR_INVAL_ARG;
        }
        for( i = 0; i < 6; ++i )
            acl_rule.src_mac[i] = (u8) values[i];
    } else if(sr_xpath_node_name_eq(val->xpath, "source-mac-mask")) {
        int values[6],i;
        if (6 != sscanf( val->data.string_val, "%2x:%2x:%2x:%2x:%2x:%2x%*c",
            &values[0], &values[1], &values[2],
            &values[3], &values[4], &values[5])) {
            SRP_LOG_ERR_MSG("Failed convert string MAC address to int.");
            return SR_ERR_INVAL_ARG;
        }
        for( i = 0; i < 6; ++i )
            acl_rule.src_mac_mask[i] = (u8) values[i];
    } else if(sr_xpath_node_name_eq(val->xpath, "protocol")) {
        acl_rule.protocol = val->data.int8_val;
    } else if(sr_xpath_node_name_eq(val->xpath, "source-port")) {
    } else if(sr_xpath_node_name_eq(val->xpath, "destination-port")) {
    } else if(sr_xpath_node_name_eq(val->xpath, "forwarding-action")) {
        if (!strcmp("openconfig-acl:ACCEPT", val->data.string_val)) {
            acl_rule.is_permit = true;//ACL::action_t::PERMIT;
        } else if (!strcmp("openconfig-acl:REJECT", val->data.string_val)) {
            acl_rule.is_permit = false;//ACL::action_t::DENY;
        }
    }

    return SR_ERR_OK;
}

/*
 * @brief Parse leaf from xpath:
 * /openconfig-acl:acl/acl-sets/acl-set<xc:operation="delete">
*/
static int parse_acl_del_entry(
    const sr_val_t *val)
{
    sr_xpath_ctx_t state = {0};

    if(sr_xpath_node_name_eq(val->xpath, "name")) {
/*
        if (sr_xpath_node(val->xpath, "config", &state)) {
            sr_xpath_recover(&state);
            mapping->sets_count++;
            acl_del_set_t *acl_sets =
                (acl_del_set_t*)calloc(mapping->sets_count,
                                       sizeof(acl_del_set_t));
            if (0 == acl_sets)
                return SR_ERR_NOMEM;
            if (mapping->sets_count > 0) {
                memcpy(acl_sets, mapping->acl_sets,
                       (mapping->sets_count-1) * sizeof(acl_del_set_t));
                free(mapping->acl_sets);
            }
            mapping->acl_sets = acl_sets;
            memcpy(mapping->acl_sets[mapping->sets_count-1].tag,
                   val->data.string_val, strlen(val->data.string_val));
        }
*/
    }
    // if (mapping->acl_sets && mapping->sets_count > 0) {
    //     acl_set = &mapping->acl_sets[mapping->sets_count-1];
    // }
    else if(sr_xpath_node_name_eq(val->xpath, "type")) {
/*        
        if (sr_xpath_node(val->xpath, "config", &state)) {
            sr_xpath_recover(&state);
            if(!strcmp("openconfig-acl:ACL_IPV4", val->data.string_val) ||
            !strcmp("openconfig-acl:ACL_IPV6", val->data.string_val)) {
                acl_set->type = ACL;
                acl_set->acl_payload.acl_index = -1;
            } else {
                acl_set->type = MACIP;
                acl_set->macip_acl_payload.acl_index = -1;
            }
        }
*/        
    }
    return SR_ERR_OK;
}

/*
 * @brief Callback to parse request to add/replace acl set(s)
*/
static int openconfig_acl_sets_change_cb(
    sr_session_ctx_t *ds, const char *xpath, sr_notif_event_t event,
    __attribute__((unused)) void *private_ctx)
{
    sr_change_iter_t *it = NULL;
    sr_change_oper_t oper;
    sr_xpath_ctx_t state = {0};
    sr_val_t *old_val, *new_val, *tmp;
    acl_set_t acl_set = {};
    acl_rule_t acl_rule = {};
    bool rule_subtree = false;
    bool create_set = false;
    bool delete_set = false;
    int rc;

    string set_name, curr_set_name;
    string rule_sid, curr_rule_sid;

    ARG_CHECK2(SR_ERR_INVAL_ARG, ds, xpath);

    if (event == SR_EV_VERIFY)
        return SR_ERR_OK;

    if (sr_get_changes_iter(ds, (char *)xpath, &it) != SR_ERR_OK) {
        sr_free_change_iter(it);
        return SR_ERR_OK;
    }

    SRP_LOG_INF("In %s", __FUNCTION__);

    foreach_change (ds, it, oper, old_val, new_val) {
        switch (oper) {
            case SR_OP_CREATED:
                create_set = true;
                tmp = new_val;
                break;
            case SR_OP_DELETED:
                delete_set = true;
                tmp = old_val;
                break;
            default:
                SRP_LOG_WRN_MSG("Operation not supported");
                continue;
        }
        SRP_LOG_DBG("A change detected in '%s', op=%d", tmp->xpath, oper);

        rule_subtree = sr_xpath_node(tmp->xpath, "acl-entry", &state)?true:false;
        sr_xpath_recover(&state);

        set_name = sr_xpath_key_value(tmp->xpath, "acl-set", "name", &state);
        sr_xpath_recover(&state);
        if (rule_subtree) {
            rule_sid = sr_xpath_key_value(tmp->xpath, "acl-entry", "sequence-id", &state);
            sr_xpath_recover(&state);
        }
        if (set_name.empty()) {
            sr_set_error(ds, "XPATH ACL name NOT found", tmp->xpath);
            return SR_ERR_INVAL_ARG;
        }
        if (set_name.compare(curr_set_name)) {
            if (!curr_set_name.empty()) {
                add_rule(acl_set, acl_rule);
                add_set(acl_set);
                acl_set.l3rules.clear();
                acl_set.l2rules.clear();
                acl_set = {};
                acl_rule = {};
                curr_rule_sid = "";
            }
            curr_set_name = set_name;
        }
        if (rule_subtree) {
            if (rule_sid.compare(curr_rule_sid)) {
                if (!curr_rule_sid.empty()) {
                    add_rule(acl_set, acl_rule);
                    acl_rule = {};
                }
                curr_rule_sid = rule_sid;
            }
        }

        switch (oper) {
            case SR_OP_CREATED:
            case SR_OP_MODIFIED:
                rc = parse_acl_set_entry(tmp, acl_set, acl_rule);
                break;
            case SR_OP_DELETED:
                rc = parse_acl_del_entry(tmp);
                break;
            case SR_OP_MOVED:
                break;
        }

        sr_free_val(old_val);
        sr_free_val(new_val);
        if (SR_ERR_OK != rc) {
            rc = SR_ERR_OPERATION_FAILED;
            break;
        }
    }

    if (create_set) {
        add_rule(acl_set, acl_rule);
        add_set(acl_set);
    }
    if (delete_set) {

    }

    sr_free_change_iter(it);
    return rc;
}

/*
 * @brief Callback to parse request to dump acl sets
*/
static int openconfig_acl_sets_state_cb(
    const char *xpath, sr_val_t **values, size_t *values_cnt,
    uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    *values = nullptr;
    *values_cnt = 0;

    return SR_ERR_OK;
}

static sr_error_t add_interface(const string if_name, const string aclset_name,
    const direction_t direction)
{
    SRP_LOG_INF("In %s", __FUNCTION__);

    try {
        string uuid = aclset_name + 
                      ((direction == direction_t::INPUT)?"_in_":"_out_") +
                      if_name;

        OM::mark_n_sweep ms(uuid);
        shared_ptr<l3_list> l3set = l3_list::find(aclset_name);
        if (nullptr != l3set) {
            shared_ptr<interface> itf = interface::find(if_name);
            if (nullptr != itf) {
                ACL::l3_binding l3b(direction, *itf, *l3set);
                OM::write(uuid, l3b);
            }
        }
    } catch (exception &exc) {
        // catch boost exception from prefix_t
        SRP_LOG_ERR("Error: %s", exc.what());
        return SR_ERR_OPERATION_FAILED;
    }

    return SR_ERR_OK;
}

/*
 * @brief Callback to parse request to add/replace acl set(s)
*/
static int openconfig_acl_interface_change_cb(
    sr_session_ctx_t *ds, const char *xpath, sr_notif_event_t event,
    __attribute__((unused)) void *private_ctx)
{
    sr_change_iter_t *it = NULL;
    sr_change_oper_t oper;
    sr_xpath_ctx_t state = {0};
    sr_val_t *old_val, *new_val, *tmp;
    bool ingress = false;
    bool egress = false;
    int rc = SR_ERR_OK;

    string interface_id, curr_interface_id;
    string set_name, type;

    ARG_CHECK2(SR_ERR_INVAL_ARG, ds, xpath);

    if (event == SR_EV_VERIFY)
        return SR_ERR_OK;

    if (sr_get_changes_iter(ds, (char *)xpath, &it) != SR_ERR_OK) {
        sr_free_change_iter(it);
        return SR_ERR_OK;
    }

    SRP_LOG_INF("In %s", __FUNCTION__);

    foreach_change (ds, it, oper, old_val, new_val) {
        switch (oper) {
            case SR_OP_CREATED:
                tmp = new_val;
                break;
            case SR_OP_DELETED:
                tmp = old_val;
                break;
            default:
                SRP_LOG_WRN_MSG("Operation not supported");
                continue;
        }
        SRP_LOG_DBG("A change detected in '%s', op=%d", tmp->xpath, oper);

        ingress = sr_xpath_node(tmp->xpath, "ingress-acl-set", &state)?true:false;
        sr_xpath_recover(&state);
        egress = sr_xpath_node(tmp->xpath, "egress-acl-set", &state)?true:false;
        sr_xpath_recover(&state);
        if (ingress || egress) {
            interface_id = sr_xpath_key_value(tmp->xpath, "interface", "id", &state);
            sr_xpath_recover(&state);
            if (ingress)
                set_name = sr_xpath_key_value(tmp->xpath, "ingress-acl-set", "set-name", &state);
            else
                set_name = sr_xpath_key_value(tmp->xpath, "egress-acl-set", "set-name", &state);
            sr_xpath_recover(&state);
            if (ingress)
                type = sr_xpath_key_value(tmp->xpath, "ingress-acl-set", "type", &state);
            else
                type = sr_xpath_key_value(tmp->xpath, "egress-acl-set", "type", &state);
            sr_xpath_recover(&state);
            if (ingress)
                add_interface(interface_id, set_name, direction_t::INPUT);
            else
                add_interface(interface_id, set_name, direction_t::OUTPUT);
        }
        
        sr_free_val(old_val);
        sr_free_val(new_val);
        if (SR_ERR_OK != rc) {
            rc = SR_ERR_OPERATION_FAILED;
            break;
        }
    }

    sr_free_change_iter(it);
    return rc;
}

int
openconfig_acl_init(sc_plugin_main_t *pm)
{
    int rc = SR_ERR_OK;
    SRP_LOG_DBG_MSG("Initializing openconfig-acl plugin.");

    rc = sr_subtree_change_subscribe(pm->session, "/openconfig-acl:acl/acl-sets/acl-set",
            openconfig_acl_sets_change_cb,
            nullptr, 98, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/openconfig-acl:acl/interfaces/interface",
            openconfig_acl_interface_change_cb,
            nullptr, 98, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(pm->session, "/openconfig-acl:acl/acl-sets/acl-set/state",
            openconfig_acl_sets_state_cb,
            nullptr, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    SRP_LOG_DBG_MSG("openconfig-acl plugin initialized successfully.");
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("Error by initialization of openconfig-acl plugin. Error : %d", rc);
    return rc;
}

void
openconfig_acl_exit(__attribute__((unused)) sc_plugin_main_t *pm)
{
}

SC_INIT_FUNCTION(openconfig_acl_init);
SC_EXIT_FUNCTION(openconfig_acl_exit);