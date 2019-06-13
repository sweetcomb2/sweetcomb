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

#include <string>
#include <exception>

#include "sc_plugins.h"

using namespace std;
using namespace VOM;

#define MODULE_NAME "openconfig-interfaces"

struct pathNode {
    bool is_add;
    bool is_ipv6;
    string address;
    pathNode *next;
};

struct infoPaths {
    pathNode *addressesList;
    pathNode *lastAddress;
};

struct keyRoute {
    string if_name;

    keyRoute(const string key) : if_name(key) {}
    bool operator<(const keyRoute& key) const {
        return (if_name.compare(key.if_name)<0);
    }
};

typedef map<keyRoute, infoPaths> TMapIPAddresses;
TMapIPAddresses mapOfIPAddresses;

// XPATH: /openconfig-interfaces:interfaces/interface[name='%s']/config/
static int openconfig_interface_change_cb(
    sr_session_ctx_t *ds, const char *xpath, sr_notif_event_t event,
    void *private_ctx)
{
    UNUSED(private_ctx);
    sr_change_iter_t *it = nullptr;
    sr_change_oper_t oper;
    sr_xpath_ctx_t state = {0};
    sr_val_t *old_val, *new_val, *tmp;
    string if_name, curr_if_name;
    string uuid;

    SRP_LOG_INF("In %s", __FUNCTION__);

    ARG_CHECK2(SR_ERR_INVAL_ARG, ds, xpath);

    if (event == SR_EV_VERIFY)
        return SR_ERR_OK;

    if (sr_get_changes_iter(ds, (char *)xpath, &it) != SR_ERR_OK) {
        sr_free_change_iter(it);
        return SR_ERR_OK;
    }

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

        if_name = sr_xpath_key_value(tmp->xpath, "interface", "name", &state);
        if (if_name.empty()) {
            sr_set_error(ds, "XPATH interface name NOT found", tmp->xpath);
            return SR_ERR_INVAL_ARG;
        }
        sr_xpath_recover(&state);

        shared_ptr<interface> intf;
        intf = interface::find(if_name);
        if (nullptr == intf) {
            SRP_LOG_ERR_MSG("Interface does not exist");
            return SR_ERR_INVAL_ARG;
        }

        if (if_name.compare(curr_if_name) || curr_if_name.empty()) {
            uuid = string(xpath) + "/" + if_name;
            curr_if_name = if_name;
        }

        // parse request
        switch (oper) {
            case SR_OP_CREATED:
            case SR_OP_MODIFIED:
                if(sr_xpath_node_name_eq(tmp->xpath, "enabled")) {
                    intf->set((tmp->data.bool_val) ?
                                interface::admin_state_t::UP :
                                interface::admin_state_t::DOWN);
                    OM::mark_n_sweep ms(uuid);
                    OM::write(uuid, *intf);
                }
                break;

            case SR_OP_DELETED:
                if(sr_xpath_node_name_eq(tmp->xpath, "enabled")) {
                    intf->set(interface::admin_state_t::DOWN);
                    OM::mark_n_sweep ms(uuid);
                    OM::write(uuid, *intf);
                }
                break;
            default:
                SRP_LOG_WRN_MSG("Operation not supported");
                continue;
        }

        sr_free_val(old_val);
        sr_free_val(new_val);
    }

    sr_free_change_iter(it);
    return SR_ERR_OK;
}

static int openconfig_interface_subinterface_change_cb(
    sr_session_ctx_t *ds, const char *xpath, sr_notif_event_t event,
    void *private_ctx)
{
    return SR_ERR_OK;
}

#define NUM_VALS_STATE_INTERFACE 7

//XPATH : /openconfig-interfaces:interfaces/interface/state
static int
openconfig_interface_state_cb(
    const char *xpath, sr_val_t **values,
    size_t *values_cnt, uint64_t request_id, const char *original_xpath,
    void *private_ctx)
{
    UNUSED(request_id); UNUSED(original_xpath); UNUSED(private_ctx);
    sr_val_t *vals = nullptr;
    sr_xpath_ctx_t state = {0};
    int cnt = 0;
    ostringstream os;

    *values = nullptr;
    *values_cnt = 0;

    const string req_if_name = sr_xpath_key_value((char*)xpath, "interface",
                                                 "name", &state);
    if (req_if_name.empty()) {
        SRP_LOG_ERR("XPATH interface name NOT found", xpath);
        return SR_ERR_INVAL_ARG;
    }
    sr_xpath_recover(&state);

    if (!sr_xpath_node_name_eq(xpath, "state"))
        return SR_ERR_INVAL_ARG;

    /* allocate array of values to be returned */
    if (0 != sr_new_values(NUM_VALS_STATE_INTERFACE, &vals))
        return SR_ERR_OPERATION_FAILED;

    SRP_LOG_INF("In %s : %s", __FUNCTION__, xpath);

    shared_ptr<interface_cmds::dump_cmd> cmd =
        make_shared<interface_cmds::dump_cmd>();
    HW::enqueue(cmd);
    HW::write();

    for (auto &itf : *cmd) {
        vapi_payload_sw_interface_details payload = itf.get_payload();
        if (req_if_name.compare((const char*)payload.interface_name))
            continue;

        //TODO need support for type propvirtual
        sr_val_build_xpath(&vals[cnt], "%s/type", xpath);
        sr_val_set_str_data(&vals[cnt++], SR_IDENTITYREF_T,
                            "iana-if-type:ethernetCsmacd");
        sr_val_build_xpath(&vals[cnt], "%s/admin-status", xpath);
        sr_val_set_str_data(&vals[cnt++], SR_ENUM_T,
                            payload.admin_up_down?"UP":"DOWN");
        sr_val_build_xpath(&vals[cnt], "%s/oper-status", xpath);
        sr_val_set_str_data(&vals[cnt++], SR_ENUM_T,
                            payload.link_up_down?"UP":"DOWN");
        sr_val_build_xpath(&vals[cnt], "%s/enabled", xpath);
        vals[cnt].type = SR_BOOL_T;
        vals[cnt++].data.bool_val = payload.admin_up_down;
        sr_val_build_xpath(&vals[cnt], "%s/mtu", xpath);
        vals[cnt].type = SR_UINT16_T;
        vals[cnt++].data.uint64_val = payload.link_mtu;
        sr_val_build_xpath(&vals[cnt], "%s/ifindex", xpath);
        vals[cnt].type = SR_UINT32_T;
        vals[cnt++].data.uint32_val = payload.sw_if_index;
    }
    *values = vals;
    *values_cnt = cnt;

    return SR_ERR_OK;
}

static void
parse_interface_ipv46_address(sr_val_t *val, string &addr,
                              uint8_t &prefix)
{
    if (nullptr == val) {
        throw runtime_error("Null pointer");
    }

    if (sr_xpath_node_name_eq(val->xpath, "ip")) {
        addr = val->data.string_val;
        // remove ending '$'
        addr.resize(addr.length()-1);
    } else if (sr_xpath_node_name_eq(val->xpath, "prefix-length")) {
        prefix = val->data.uint8_val;
    }
}

static int
ipv46_config_add_del(const string &uuid, const string &if_name,
                     const string &addr, uint8_t prefix, bool is_add)
{
    shared_ptr<interface> intf = interface::find(if_name);
    if (nullptr == intf) {
        SRP_LOG_ERR_MSG("Interfaces does not exist");
        return SR_ERR_INVAL_ARG;
    }

    try {
        if (is_add) {
            route::prefix_t pfx(addr, prefix);
            l3_binding l3(*intf, pfx);
            OM::mark_n_sweep ms(uuid+addr);
            OM::write(uuid+addr, l3);
        }
    } catch (exception &exc) {
        // catch boost exception from prefix_t
        SRP_LOG_ERR("Error: %s", exc.what());
        return SR_ERR_OPERATION_FAILED;
    }

    return SR_ERR_OK;
}
/*
#define ROOT "/openconfig-local-routing:local-routes/static-routes/static[prefix='%s']/next-hops/next-hop[index='%s']/%s"

static inline char*
_get_ds_elem(sr_session_ctx_t *sess, const char *prefix,
             const char *index, const char *sub)
{
    char xpath[XPATH_SIZE] = {0};
    sr_val_t *value = NULL;
    int rc;

    snprintf(xpath, XPATH_SIZE, ROOT, prefix, index, sub);

    rc = sr_get_item(sess, xpath, &value);
    if (SR_ERR_OK != rc) {
        SRP_LOG_DBG("XPATH %s not set", xpath);
        return NULL;
    }

    return value->data.string_val;
}
*/
// XPATH: openconfig-interfaces:interfaces/interface[name='%s']/subinterfaces/subinterface[index='%s']/oc-ip:ipv4/oc-ip:addresses/oc-ip:address[ip='%s']/oc-ip:config/
static int openconfig_interface_ip_config_cb(
    sr_session_ctx_t *ds, const char *xpath, sr_notif_event_t event,
    void *private_ctx)
{
    UNUSED(private_ctx);
    sr_change_iter_t *iter = nullptr;
    sr_change_oper_t oper = SR_OP_CREATED;
    sr_val_t *old_val, *new_val, *tmp;
    sr_xpath_ctx_t state = { 0, };
    string new_addr, old_addr;
    string if_name, subif_index, curr_if_name;
    uint8_t new_prefix = 0;
    uint8_t old_prefix = 0;
    int op_rc = SR_ERR_OK;
    int curr_sub_idx = -1, sub_idx;
    string uuid;

    if (event == SR_EV_VERIFY)
        return SR_ERR_OK;

    if (sr_get_changes_iter(ds, (char *)xpath, &iter) != SR_ERR_OK) {
        sr_free_change_iter(iter);
        return SR_ERR_OK;
    }

    foreach_change (ds, iter, oper, old_val, new_val) {
        switch (oper) {
            case SR_OP_CREATED:
                tmp = new_val;
                break;
            case SR_OP_DELETED:
                tmp = old_val;
                continue;
            default:
                SRP_LOG_WRN_MSG("Operation not supported");
                continue;
        }

        SRP_LOG_DBG("A change detected in '%s', op=%d", tmp->xpath, oper);
        if_name = sr_xpath_key_value(tmp->xpath, "interface", "name", &state);
        sr_xpath_recover(&state);
        subif_index = sr_xpath_key_value(tmp->xpath, "subinterface", "index", &state);
        sub_idx = stoi(subif_index);
        sr_xpath_recover(&state);

        if (curr_sub_idx != sub_idx) {
            curr_sub_idx = sub_idx;
        }
        if (if_name.compare(curr_if_name) || curr_if_name.empty()) {
            uuid = string("ipv46_address/") +
                   to_string(oper) + "/" +
                   if_name +  "/" + to_string(curr_sub_idx) +  "/";
            curr_if_name = if_name;
        }

        try {
            switch (oper) {
                case SR_OP_CREATED:
                    parse_interface_ipv46_address(tmp, new_addr, new_prefix);
                    break;
                case SR_OP_DELETED:
                    // parse_interface_ipv46_address(tmp, old_addr, old_prefix);
                    break;
            }
        } catch (exception &exc) {
            SRP_LOG_ERR("Error: %s", exc.what());
        }
        sr_free_val(old_val);
        sr_free_val(new_val);

        // if (!old_addr.empty() && old_prefix > 0) {
        //     op_rc = ipv46_config_add_del(uuid, if_name, new_addr, new_prefix, false);
        //     old_prefix = 0;
        // }
        if (!new_addr.empty() && new_prefix > 0) {
            op_rc = ipv46_config_add_del(uuid, if_name, new_addr, new_prefix, true);
            new_prefix = 0;
        }
    }
    sr_free_change_iter(iter);

    return op_rc;
}

#define NUM_VALS_STATE_SUBINTERFACE     2
#define NUM_VALS_STATE_SUBINTERFACE_IP  3

static int openconfig_interface_subif_state_cb(
    const char *xpath, sr_val_t **values, size_t *values_cnt,
    uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    UNUSED(request_id); UNUSED(original_xpath); UNUSED(private_ctx);
    sr_val_t *val = nullptr;
    sr_xpath_ctx_t state = {0};
    int cnt = 0;

    *values = nullptr;
    *values_cnt = 0;

    const string req_if_name = sr_xpath_key_value((char*)xpath, "interface",
                                                  "name", &state);
    if (req_if_name.empty()) {
        SRP_LOG_ERR("XPATH interface name NOT found", xpath);
        return SR_ERR_INVAL_ARG;
    }
    sr_xpath_recover(&state);

    if (!sr_xpath_node_name_eq(xpath, "state"))
        return SR_ERR_INVAL_ARG;

    // allocate array of values to be returned
    if (0 != sr_new_values(NUM_VALS_STATE_SUBINTERFACE, &val))
        return SR_ERR_OPERATION_FAILED;;

    SRP_LOG_INF("In %s, %s", __FUNCTION__, xpath);

    // Retrieve ip addresses using l3_binding dump
    shared_ptr<interface_cmds::dump_cmd> cmd =
        make_shared<interface_cmds::dump_cmd>();
    HW::enqueue(cmd);
    HW::write();

    for (auto &itf : *cmd) {
        vapi_payload_sw_interface_details payload = itf.get_payload();
        if (req_if_name.compare((const char*)payload.interface_name))
            continue;

        sr_val_build_xpath(&val[cnt], "%s/index", xpath);
        val[cnt].type = SR_UINT32_T;
        val[cnt++].data.uint32_val = payload.sw_if_index;
        sr_val_build_xpath(&val[cnt], "%s/ifindex", xpath);
        val[cnt].type = SR_UINT32_T;
        val[cnt++].data.uint32_val = payload.sup_sw_if_index;
    }
    *values = val;
    *values_cnt = cnt;

    return SR_ERR_OK;
}

static int openconfig_subinterface_ip_state_cb(
    const char *xpath, sr_val_t **values, size_t *values_cnt,
    uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    UNUSED(request_id); UNUSED(original_xpath); UNUSED(private_ctx);
    sr_val_t *val = nullptr;
    sr_xpath_ctx_t state = {0};
    int cnt = 0;

    int l3_bindings_num = 0;

    *values = nullptr;
    *values_cnt = 0;

SRP_LOG_INF_MSG("0");

    const string req_if_name = sr_xpath_key_value((char*)xpath, "interface",
                                                  "name", &state);
    if (req_if_name.empty()) {
        SRP_LOG_ERR("XPATH interface name NOT found", xpath);
        return SR_ERR_INVAL_ARG;
    }
    sr_xpath_recover(&state);

SRP_LOG_INF_MSG("0");

    if (!sr_xpath_node_name_eq(xpath, "state"))
        return SR_ERR_INVAL_ARG;

    SRP_LOG_INF("In %s, %s", __FUNCTION__, xpath);

    // FIXME : Sysrepo reports error when creating response
/*
    //TODO: Not effective
    for (auto inter = l3_binding::cbegin(); inter != l3_binding::cend(); inter++) {
        l3_bindings_num++;
    }

    // allocate array of values to be returned
    if (0 != sr_new_values((l3_bindings_num + 1) * NUM_VALS_STATE_INTERFACE_IP, &val))
        return SR_ERR_OPERATION_FAILED;;

    // Retrieve ip addresses from l3 bindings
    for (auto l3 = l3_binding::cbegin(); l3 != l3_binding::cend(); l3++) {
        shared_ptr<l3_binding> l3_binding = l3->second.lock();
        // L3-binding:[interface:[loop0 ... ]] prefix:10.0.0.2/32 hw-item:[rc:ok data:1]]
        //                              ... ]] prefix:10.0.0.2/0 hw-item:[rc:invalid data:1]
        string l3_dump = l3_binding->to_string();
        string l3_if_name = l3_dump.substr(23, l3_dump.find(" ")-23);
        if (req_if_name.compare(l3_if_name))
            continue;

        SRP_LOG_INF("L3 bindings prefix : %s", l3_binding->prefix().to_string().c_str());

        size_t sep1 = l3_dump.find("prefix:");
        if (sep1 != string::npos && l3_dump.find("rc:ok", sep1) < l3_dump.length())
        {
            char address_ip[VPP_IP6_ADDRESS_STRING_LEN+1] = {0};
            u8 prefix_length;

            string xpath_root = string(xpath);
            xpath_root.resize(strlen(xpath) - 6);
            string addr = l3_dump.substr(sep1+7, l3_dump.find(" ", sep1)-sep1-7);
            prefix2ip4(address_ip, addr.c_str(), &prefix_length);
            strcat(address_ip, "$");

            xpath_root += "/oc-ip:ipv4/oc-ip:addresses/oc-ip:address[ip='";
            xpath_root += address_ip;
            xpath_root += "']/oc-ip:state";

            sr_val_build_xpath(&val[cnt], "%s/oc-ip:ip", xpath_root.c_str());
            sr_val_set_str_data(&val[cnt], SR_STRING_T, address_ip);
            cnt++;

            sr_val_build_xpath(&val[cnt], "%s/oc-ip:prefix-length", xpath_root.c_str());
            val[cnt].type = SR_UINT8_T;
            val[cnt].data.uint8_val = prefix_length;
            cnt++;
        }
    }
*/
    // Retrieve ip addresses using l3_binding dump
    shared_ptr<interface> itf = interface::find(req_if_name);
    if (nullptr != itf) {
        shared_ptr<l3_binding_cmds::dump_v4_cmd> dipv4 =
        make_shared<l3_binding_cmds::dump_v4_cmd>(
            l3_binding_cmds::dump_v4_cmd(itf->handle()));
        HW::enqueue(dipv4);
        // TODO: IPv6 dump not implemented in VOM

        // shared_ptr<l3_binding_cmds::dump_v6_cmd> dipv6 =
        // make_shared<l3_binding_cmds::dump_v6_cmd>(
        //     l3_binding_cmds::dump_v6_cmd(itf->handle()));
        // HW::enqueue(dipv6);
        HW::write();

        //TODO: Not effective
        for (auto& l3_record : *dipv4)
            l3_bindings_num++;
        // for (auto& l3_record : *dipv6)
        //     l3_bindings_num++;

        // allocate array of values to be returned
        if (0 != sr_new_values((l3_bindings_num + 1) * NUM_VALS_STATE_SUBINTERFACE_IP, &val))
            return SR_ERR_OPERATION_FAILED;;

        char ip_address[INET6_ADDRSTRLEN+1];

        for (auto& l3_record : *dipv4) {
            vapi_payload_ip_address_details payload = l3_record.get_payload();
            if (sc_ntop((!payload.is_ipv6) ? AF_INET : AF_INET6, payload.ip, ip_address)) {
                strcat(ip_address, "$");
                sr_val_build_xpath(&val[cnt], "%s/openconfig-if-ip:ip", xpath);
                sr_val_set_str_data(&val[cnt++], SR_STRING_T, ip_address);
                sr_val_build_xpath(&val[cnt], "%s/openconfig-if-ip:prefix-length", xpath);
                val[cnt].type = SR_UINT8_T;
                val[cnt++].data.uint8_val = payload.prefix_length;
            }
        }
        // for (auto& l3_record : *dipv6) {
        // }
    }
    *values = val;
    *values_cnt = cnt;

    return SR_ERR_OK;
}

int
openconfig_interface_init(sc_plugin_main_t *pm)
{
    int rc = SR_ERR_OK;
    SRP_LOG_DBG_MSG("Initializing openconfig-interfaces plugin.");

    rc = sr_subtree_change_subscribe(pm->session, "/openconfig-interfaces:interfaces/interface/config",
            openconfig_interface_change_cb,
            nullptr, 98, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(pm->session, "/openconfig-interfaces:interfaces/interface/state",
            openconfig_interface_state_cb,
            nullptr, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/config",
            openconfig_interface_subinterface_change_cb,
            nullptr, 97, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(pm->session, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/state",
            openconfig_interface_subif_state_cb,
            nullptr, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session,
            "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/openconfig-if-ip:addresses/openconfig-if-ip:address/openconfig-if-ip:config",
            openconfig_interface_ip_config_cb,
            nullptr, 100, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session,
            "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/openconfig-if-ip:addresses/openconfig-if-ip:address/openconfig-if-ip:config",
            openconfig_interface_ip_config_cb,
            nullptr, 100, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(pm->session,
            "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/openconfig-if-ip:addresses/openconfig-if-ip:address/openconfig-if-ip:state",
            openconfig_subinterface_ip_state_cb,
            nullptr, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(pm->session,
            "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/openconfig-if-ip:addresses/openconfig-if-ip:address/openconfig-if-ip:state",
            openconfig_subinterface_ip_state_cb,
            nullptr, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    SRP_LOG_DBG_MSG("openconfig-interfaces plugin initialized successfully.");
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("Error by initialization of openconfig-interfaces plugin. Error : %d", rc);
    return rc;
}

void
openconfig_interface_exit(__attribute__((unused)) sc_plugin_main_t *pm)
{
}

SC_INIT_FUNCTION(openconfig_interface_init);
SC_EXIT_FUNCTION(openconfig_interface_exit);
