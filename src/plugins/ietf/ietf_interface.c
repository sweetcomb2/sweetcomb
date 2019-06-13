/*
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

#include <stdio.h>
#include <iomanip>
#include <sys/socket.h>

#include <vom/om.hpp>
#include <vom/interface.hpp>
#include <vom/interface_cmds.hpp>
#include <vom/l3_binding.hpp>
#include <vom/l3_binding_cmds.hpp>

#include <string>
#include <exception>

#include <stdlib.h>

#include "sc_plugins.h"

using namespace std;
using namespace VOM;

#define MODULE_NAME "ietf-interfaces"

/**
 * @brief Callback to be called by any config change of
 * "/ietf-interfaces:interfaces/interface/enabled" leaf.
 */
static int
ietf_interface_enable_disable_cb(sr_session_ctx_t *session, const char *xpath,
                                 sr_notif_event_t event, void *private_ctx)
{
    UNUSED(private_ctx);
    char *if_name = nullptr;
    sr_change_iter_t *iter = nullptr;
    sr_change_oper_t op = SR_OP_CREATED;
    sr_val_t *old_val = nullptr;
    sr_val_t *new_val = nullptr;
    sr_xpath_ctx_t xpath_ctx = { 0, };
    int rc = SR_ERR_OK, op_rc = SR_ERR_OK;
    rc_t vom_rc = rc_t::OK;

    SRP_LOG_INF("In %s", __FUNCTION__);

    /* no-op for apply, we only care about SR_EV_ENABLED, SR_EV_VERIFY, SR_EV_ABORT */
    if (SR_EV_APPLY == event)
        return SR_ERR_OK;

    SRP_LOG_DBG("'%s' modified, event=%d", xpath, event);

    /* get changes iterator */
    rc = sr_get_changes_iter(session, xpath, &iter);
    if (SR_ERR_OK != rc) {
        sr_free_change_iter(iter);
        SRP_LOG_ERR("Unable to retrieve change iterator: %s", sr_strerror(rc));
        return rc;
    }

    foreach_change (session, iter, op, old_val, new_val) {

        SRP_LOG_DBG("A change detected in '%s', op=%d", new_val ? new_val->xpath : old_val->xpath, op);
        if_name = sr_xpath_key_value(new_val ? new_val->xpath : old_val->xpath, "interface", "name", &xpath_ctx);

        shared_ptr<interface> intf;
        intf = interface::find(if_name);
        if (nullptr == intf) {
            SRP_LOG_ERR_MSG("Interface does not exist");
            return SR_ERR_INVAL_ARG;
        }

        switch (op) {
            case SR_OP_CREATED:
            case SR_OP_MODIFIED:
                if (new_val->data.bool_val) {
                    intf->set(interface::admin_state_t::UP);
                } else {
                    intf->set(interface::admin_state_t::DOWN);
                }
                break;
            case SR_OP_DELETED:
                intf->set(interface::admin_state_t::DOWN);
                break;
            default:
                break;
        }
        sr_xpath_recover(&xpath_ctx);
        if (SR_ERR_INVAL_ARG == op_rc) {
            sr_set_error(session, "Invalid interface name.", new_val ? new_val->xpath : old_val->xpath);
        }
        sr_free_val(old_val);
        sr_free_val(new_val);

        vom_rc = OM::write(MODULE_NAME, *intf);
        if (rc_t::OK != vom_rc) {
            SRP_LOG_ERR_MSG("Error write data to vpp");
        } else {
            SRP_LOG_DBG_MSG("Data written to vpp");
        }
    }
    sr_free_change_iter(iter);

    return op_rc;
}

static int
ipv46_config_add_remove(const string &if_name,
                        const string &addr, uint8_t prefix,
                        bool add)
{
    l3_binding *l3;
    rc_t rc = rc_t::OK;

    shared_ptr<interface> intf = interface::find(if_name);
    if (nullptr == intf) {
        SRP_LOG_ERR_MSG("Interfaces does not exist");
        return SR_ERR_INVAL_ARG;
    }

    try {
        route::prefix_t pfx(addr, prefix);
        l3 = new l3_binding(*intf, pfx);
        HW::item<handle_t> hw_ifh(2, rc_t::OK);
        HW::item<bool> hw_l3_bind(true, rc_t::OK);
        if (add) {
            l3_binding_cmds::bind_cmd(hw_l3_bind, hw_ifh.data(), pfx);
        } else {
            l3_binding_cmds::unbind_cmd(hw_l3_bind, hw_ifh.data(), pfx);
        }
    } catch (std::exception &exc) {  //catch boost exception from prefix_t
        SRP_LOG_ERR("Error: %s", exc.what());
        return SR_ERR_OPERATION_FAILED;
    }

    rc = OM::write(MODULE_NAME, *l3);
    if (rc_t::OK != rc) {
        SRP_LOG_ERR_MSG("Error write data to vpp");
        return SR_ERR_OPERATION_FAILED;
    }
    SRP_LOG_DBG_MSG("Data written to vpp");

    return SR_ERR_OK;
}

static void
parse_interface_ipv46_address(sr_val_t *val, string &addr,
                              uint8_t &prefix)
{
    if (nullptr == val) {
        throw runtime_error("Null pointer");
    }

    if (SR_LIST_T == val->type) {
        /* create on list item - reset state vars */
        addr.clear();
    } else {
        if (sr_xpath_node_name_eq(val->xpath, "ip")) {
            addr = val->data.string_val;
        } else if (sr_xpath_node_name_eq(val->xpath, "prefix-length")) {
            prefix = val->data.uint8_val;
        } else if (sr_xpath_node_name_eq(val->xpath, "netmask")) {
            prefix = netmask_to_prefix(val->data.string_val);
        }
    }
}

/**
 * @brief Callback to be called by any config change in subtrees
 * "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address"
 * or "/ietf-interfaces:interfaces/interface/ietf-ip:ipv6/address".
 */
static int
ietf_interface_ipv46_address_change_cb(sr_session_ctx_t *session,
                                       const char *xpath,
                                       sr_notif_event_t event,
                                       void *private_ctx)
{
    UNUSED(private_ctx);
    sr_change_iter_t *iter = nullptr;
    sr_change_oper_t op = SR_OP_CREATED;
    sr_val_t *old_val = nullptr;
    sr_val_t *new_val = nullptr;
    sr_xpath_ctx_t xpath_ctx = { 0, };
    string new_addr, old_addr;
    string if_name;
    uint8_t new_prefix = 0;
    uint8_t old_prefix = 0;
    int rc = SR_ERR_OK, op_rc = SR_ERR_OK;
    bool create = false;
    bool del = false;

    SRP_LOG_INF("In %s", __FUNCTION__);

    /* no-op for apply, we only care about SR_EV_ENABLED, SR_EV_VERIFY, SR_EV_ABORT */
    if (SR_EV_APPLY == event) {
        return SR_ERR_OK;
    }
    SRP_LOG_DBG("'%s' modified, event=%d", xpath, event);

    sr_xpath_recover(&xpath_ctx);

    /* get changes iterator */
    rc = sr_get_changes_iter(session, xpath, &iter);
    if (SR_ERR_OK != rc) {
        sr_free_change_iter(iter);
        SRP_LOG_ERR("Unable to retrieve change iterator: %s", sr_strerror(rc));
        return rc;
    }

    foreach_change(session, iter, op, old_val, new_val) {

        SRP_LOG_DBG("A change detected in '%s', op=%d",
                    new_val ? new_val->xpath : old_val->xpath, op);
        if_name = sr_xpath_key_value(new_val ? new_val->xpath : old_val->xpath,
                                     "interface", "name", &xpath_ctx);
        sr_xpath_recover(&xpath_ctx);

        try {
            switch (op) {
                case SR_OP_CREATED:
                    create = true;
                    parse_interface_ipv46_address(new_val, new_addr, new_prefix);
                    break;
                case SR_OP_MODIFIED:
                    create = true;
                    del = true;
                    parse_interface_ipv46_address(old_val, old_addr, old_prefix);
                    parse_interface_ipv46_address(new_val, new_addr, new_prefix);
                    break;
                case SR_OP_DELETED:
                    del = true;
                    parse_interface_ipv46_address(old_val, old_addr, old_prefix);
                    break;
                default:
                    break;
            }
        } catch (std::exception &exc) {
            SRP_LOG_ERR("Error: %s", exc.what());
        }
        sr_free_val(old_val);
        sr_free_val(new_val);

        if (del && !old_addr.empty()) {
            op_rc = ipv46_config_add_remove(if_name, old_addr, old_prefix,
                                            false /* del */);
        }

        if (create && !new_addr.empty()) {
            op_rc = ipv46_config_add_remove(if_name, new_addr, new_prefix,
                                            true /* add */);
        }

    }
    sr_free_change_iter(iter);

    return op_rc;
}

/**
 * @brief Callback to be called by any config change under "/ietf-interfaces:interfaces-state/interface" path.
 * Does not provide any functionality, needed just to cover not supported config leaves.
 */
static int
ietf_interface_change_cb(sr_session_ctx_t *session, const char *xpath,
                         sr_notif_event_t event, void *private_ctx)
{
    UNUSED(session); UNUSED(xpath); UNUSED(event); UNUSED(private_ctx);

    struct stat st = {0};
    const char cmd[] = "/usr/bin/sysrepocfg --format=json -x "\
    "/tmp/sweetcomb/ietf-interfaces.json --datastore=running ietf-interfaces &";
    int rc = 0;

    SRP_LOG_INF("In %s", __FUNCTION__);

    if (!export_backup) {
        return SR_ERR_OK;
    }

    if (-1 == stat(BACKUP_DIR_PATH, &st)) {
        mkdir(BACKUP_DIR_PATH, 0700);
    }

    rc = system(cmd);
    if (0 != rc) {
        SRP_LOG_ERR("Failed restore backup for module: ietf-interfaces, errno: %s",
                    strerror(errno));
    }
    SRP_LOG_DBG_MSG("ietf-interfaces modules, backup");

    return SR_ERR_OK;
}

#define NUM_VALS_STATE_INTERFACE    5
#define NUM_VALS_STATE_INTERFACE_IP 1

/**
 * @brief Callback to be called by any request for state data under "/ietf-interfaces:interfaces-state/interface" path.
 */
static int
ietf_interface_state_cb(const char *xpath, sr_val_t **values,
                        size_t *values_cnt, uint64_t request_id,
                        const char *original_xpath, void *private_ctx)
{
    UNUSED(request_id); UNUSED(original_xpath); UNUSED(private_ctx);
    struct elt* stack;
    sr_val_t *vals = nullptr;
    sr_xpath_ctx_t state = {0};
    int vals_cnt = 0;
    int cnt = 0;

    *values = nullptr;
    *values_cnt = 0;

    // if (!sr_xpath_node_name_eq(xpath, "interfaces-state"))
    //     return SR_ERR_INVAL_ARG;

    SRP_LOG_INF("In %s, %s", __FUNCTION__, xpath);

    // Retrieve ip addresses using l3_binding dump
    shared_ptr<interface_cmds::dump_cmd> cmd =
        make_shared<interface_cmds::dump_cmd>();
    HW::enqueue(cmd);
    HW::write();

        //TODO: Not effective
    for (auto &it : *cmd) {
        vals_cnt += NUM_VALS_STATE_INTERFACE;

        vapi_payload_sw_interface_details payload = it.get_payload();
        shared_ptr<interface> itf = interface::find((char*)payload.interface_name);
        if (nullptr != itf) {
            shared_ptr<l3_binding_cmds::dump_v4_cmd> dipv4 =
            make_shared<l3_binding_cmds::dump_v4_cmd>(
                l3_binding_cmds::dump_v4_cmd(itf->handle()));
            HW::enqueue(dipv4);
            // shared_ptr<l3_binding_cmds::dump_v6_cmd> dipv6 =
            // make_shared<l3_binding_cmds::dump_v6_cmd>(
            //     l3_binding_cmds::dump_v6_cmd(itf->handle()));
            // HW::enqueue(dipv6);
            HW::write();

            for (auto& l3_record : *dipv4)
                vals_cnt += NUM_VALS_STATE_INTERFACE_IP;
            // for (auto& l3_record : *dipv6)
            //     vals_cnt += NUM_VALS_STATE_INTERFACE_IP;
        }
    }

    /* allocate array of values to be returned */
    if (0 != sr_new_values(vals_cnt, &vals))
        return SR_ERR_OPERATION_FAILED;

    for (auto &it : *cmd) {
        vapi_payload_sw_interface_details payload = it.get_payload();
        //TODO need support for type propvirtual
        sr_val_build_xpath(&vals[cnt], "%s/interface[name='%s']/type", xpath,
                            payload.interface_name);
        sr_val_set_str_data(&vals[cnt++], SR_IDENTITYREF_T,
                            "iana-if-type:ethernetCsmacd");
        sr_val_build_xpath(&vals[cnt], "%s/interface[name='%s']/admin-status", xpath,
                            payload.interface_name);
        sr_val_set_str_data(&vals[cnt++], SR_ENUM_T,
                            payload.admin_up_down?"up":"down");
        sr_val_build_xpath(&vals[cnt], "%s/interface[name='%s']/oper-status", xpath,
                            payload.interface_name);
        sr_val_set_str_data(&vals[cnt++], SR_ENUM_T,
                            payload.link_up_down?"up":"down");
        sr_val_build_xpath(&vals[cnt], "%s/interface[name='%s']/speed", xpath,
                            payload.interface_name);
        vals[cnt].type = SR_UINT64_T;
        vals[cnt++].data.uint64_val = payload.link_mtu;
        if (payload.l2_address_length > 0) {
            stringstream l2_address;
            l2_address << setfill('0') << setw(2) << hex << static_cast<int>(payload.l2_address[0]);
            for (auto i=1;i<payload.l2_address_length;i++)
                l2_address << ":" << setfill('0') << setw(2) << hex << static_cast<int>(payload.l2_address[i]);
            sr_val_build_xpath(&vals[cnt], "%s/interface[name='%s']/phys-address", xpath,
                                payload.interface_name);
            sr_val_build_str_data(&vals[cnt++], SR_STRING_T, "%s",
                                l2_address.str().c_str());
        }

        //TODO: Not effective
        shared_ptr<interface> itf = interface::find((char*)payload.interface_name);
        if (nullptr != itf) {
            shared_ptr<l3_binding_cmds::dump_v4_cmd> dipv4 =
            make_shared<l3_binding_cmds::dump_v4_cmd>(
                l3_binding_cmds::dump_v4_cmd(itf->handle()));
            HW::enqueue(dipv4);
            HW::write();

            char ip_address[INET6_ADDRSTRLEN+1];
            for (auto& l3_record : *dipv4) {
                vapi_payload_ip_address_details l3_payload = l3_record.get_payload();
                if (sc_ntop(AF_INET, l3_payload.ip, ip_address)) {
                    sr_val_build_xpath(&vals[cnt], "%s/interface[name='%s']/ietf-ip:ipv4/ietf-ip:address[ietf-ip:ip='%s']/ietf-ip:prefix-length", xpath, payload.interface_name, ip_address);
                    vals[cnt].type = SR_UINT8_T;
                    vals[cnt++].data.uint8_val = l3_payload.prefix_length;
                }
            }
            // for (auto& l3_record : *dipv6) {
            //     vapi_payload_ip6_address_details l3_payload = l3_record.get_payload();
            //     if (sc_ntop(AF_INET6, l3_payload.ip, ip_address)) {
            //         sr_val_build_xpath(&vals[cnt], "%s/interface[name='%s']/ietf-ip:ipv6/ietf-ip:address[ietf-ip:ip='%s']/ietf-ip:prefix-length", xpath, payload.interface_name, ip_address);
            //         vals[cnt].type = SR_UINT8_T;
            //         vals[cnt++].data.uint8_val = l3_payload.prefix_length;
            //     }
            // }
        }
    }

    *values = vals;
    *values_cnt = cnt;

    return SR_ERR_OK;
}


int
ietf_interface_init(sc_plugin_main_t *pm)
{
    int rc = SR_ERR_OK;
    SRP_LOG_DBG_MSG("Initializing ietf-interface plugin.");

    rc = sr_subtree_change_subscribe(pm->session, "/ietf-interfaces:interfaces/interface",
            ietf_interface_change_cb, nullptr, 0, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/ietf-interfaces:interfaces/interface/enabled",
            ietf_interface_enable_disable_cb, nullptr, 100, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address",
            ietf_interface_ipv46_address_change_cb, nullptr, 99, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/ietf-interfaces:interfaces/interface/ietf-ip:ipv6/address",
            ietf_interface_ipv46_address_change_cb, nullptr, 98, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(pm->session, "/ietf-interfaces:interfaces-state",
            ietf_interface_state_cb, nullptr, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    SRP_LOG_DBG_MSG("ietf-interface plugin initialized successfully.");
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("Error by initialization of ietf-interface plugin. Error : %d", rc);
    return rc;
}

void
ietf_interface_exit(__attribute__((unused)) sc_plugin_main_t *pm)
{
}

SC_INIT_FUNCTION(ietf_interface_init);
SC_EXIT_FUNCTION(ietf_interface_exit);
