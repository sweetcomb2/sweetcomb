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

#include <assert.h>

#include <vom/om.hpp>
#include <vom/route.hpp>
#include <vom/api_types.hpp>
#include <vapi/ip.api.vapi.hpp>
#include <vpp-oper/route.hpp>

#include <string>
#include <map>
#include <exception>

#include "sc_plugins.h"

using namespace boost;
using namespace std;
using namespace VOM;


/*
 * /openconfig-local-routing:local-routes/static-routes/static/config
 * Create an FIB entry with a prefix
 */
static int
oc_static_config_cb(sr_session_ctx_t *ds, const char *xpath,
                    sr_notif_event_t event, void *private_ctx)
{
    UNUSED(private_ctx);
    sr_change_iter_t *iter = nullptr;
    sr_val_t *ol = nullptr;
    sr_val_t *ne = nullptr;
    sr_change_oper_t oper;
    int rc;

    SRP_LOG_INF("In %s", __FUNCTION__);

    if (event != SR_EV_VERIFY)
        return SR_ERR_OK;

    rc = sr_get_changes_iter(ds, xpath, &iter);
    if (rc != SR_ERR_OK) {
        sr_free_change_iter(iter);
        SRP_LOG_ERR("Unable to retrieve change iterator: %s", sr_strerror(rc));
        return SR_ERR_OPERATION_FAILED;
    }

    foreach_change(ds, iter, oper, ol, ne) {
        switch (oper) {
        case SR_OP_CREATED:
            if (sr_xpath_node_name_eq(ne->xpath, "prefix")) {
                utils::prefix p(ne->data.string_val);
                route::prefix_t prefix(p.address(), p.prefix_length());
                route::ip_route route(prefix);
                #define KEY(p) "prefix_" + p.to_string()
                if ( OM::write(KEY(p), route) != rc_t::OK ) {
                    sr_free_val(ol);
                    sr_free_val(ne);
                    sr_free_change_iter(iter);
                    SRP_LOG_ERR_MSG("Fail writing changes to VPP");
                    return SR_ERR_OPERATION_FAILED;
                }
            }
            break;

        case SR_OP_DELETED:
            if (sr_xpath_node_name_eq(ol->xpath, "prefix")) {
                utils::prefix p(ol->data.string_val);
                OM::remove(KEY(p));
                #undef KEY
            }
            break;
        }

        sr_free_val(ol);
        sr_free_val(ne);
    }

    sr_free_change_iter(iter);

    return SR_ERR_OK;
}


class route_builder {
public:
    route_builder() {}

private:
    string m_prefix;
    string m_address;
    string m_interface;
};

//static inline int
//set_route(const string uuid, const char *prefix, pathNode *pathList)
//{
//    boost::asio::ip::address nh;
//
//    // Put prefix length in mask and prefix IP in prefix
//
//    try {
//        route::ip_route rt(vompfx);
//
//        pathNode *node = pathList;
//        do {
//            nh = boost::asio::ip::address::from_string(node->path.c_str());
//            route::path path(0, nh);
//            (node->is_add) ? rt.add(path) : rt.remove(path);
//            OM::write(uuid, rt);
//            SRP_LOG_DBG("OM::WRITE ... %s", uuid.c_str());
//            node = node->next;
//        } while (node != 0);
//    } catch (std::exception &exc) { // catch boost exception from prefix_t
//        SRP_LOG_ERR("Error: %s", exc.what());
//        return SR_ERR_OPERATION_FAILED;
//    }
//
//    return SR_ERR_OK;
//}


// XPATH: /openconfig-local-routing:local-routes/static-routes/static[prefix='%s']/next-hops/next-hop[index='%s']/
//static int
//oc_next_hop_config_cb(sr_session_ctx_t *ds, const char *xpath,
//                      sr_notif_event_t event, void *private_ctx)
//{
//    UNUSED(private_ctx);
//    route_builder builder;
//    string xprefix, xindex; //prefix and next-hop index from xpath
//    string next_hop, interface, ind;
//    int index;
//    sr_change_iter_t *iter = nullptr;
//    sr_xpath_ctx_t state = {0};
//    sr_val_t *ol = nullptr;
//    sr_val_t *ne = nullptr;
//    sr_change_oper_t oper;
//    bool create, remove, modify;
//    int rc:
//
//    SRP_LOG_INF("In %s", __FUNCTION__);
//
//    if (event != SR_EV_VERIFY)
//        return SR_ERR_OK;
//
//    rc = sr_get_changes_iter(ds, xpath, &iter);
//    if (rc != SR_ERR_OK) {
//        sr_free_change_iter(iter);
//        SRP_LOG_ERR("Unable to retrieve change iterator: %s", sr_strerror(rc));
//        return SR_ERR_OPERATION_FAILED;
//    }
//
//    foreach_change(ds, iter, oper, ol, ne) {
//
//        switch (oper) {
//            case SR_OP_MODIFIED:
//                /* Create a VOM prefix instance from XPATH key */
//                prefix = sr_xpath_key_value(ne->xpath, "static", "prefix", &state);
//                if (prefix.empty()) {
//                    SRP_LOG_ERR("XPATH prefix NOT found", xpath);
//                    return SR_ERR_INVAL_ARG;
//                }
//                sr_xpath_recover(&state);
//                utils::prefix p(prefix);
//                route::prefix_t vompfx(p.address(), p.prefix_length());
//
//                /* Create a VOM path */
//                route::path();
//
//                break;
//
//            case SR_OP_CREATED:
//                if (sr_xpath_node_name_eq(ne->xpath, "index")) {
//                    builder.set_index(new_val->data.uint32_val)
//                    create = true;
//                } else if (sr_xpath_node_name_eq(ne->xpath, "next-hop")) {
//                    boost::asio::ip::address addr(ne->data.string_val);
//                    builder.set_nh(addr);
//                } else if (sr_xpath_node_name_eq(ne->xpath, "metric")) {
//                    builder.set_();
//
//                } else {
//                    SRP_LOG_WRN_MSG("Unsupported field");
//                    rc = SR_ERR_INVAL_ARG;
//                    goto nothing_todo;
//                }
//                break;
//
//            case SR_OP_DELETED:
//
//                break;
//
//            default:
//                SRP_LOG_WRN_MSG("Operation not supported");
//                continue;
//        }
//
//        sr_free_val(old_val);
//        sr_free_val(new_val);
//    }
//
//    sr_free_change_iter(iter);
//
//    return SR_ERR_OK;
//
//nothing_todo:
//    sr_free_val(old_val);
//    sr_free_val(new_val);
//    sr_free_change_iter(iter);
//    return rc;
//}

// XPATH /openconfig-local-routing:local-routes/static-routes/static/next-hops/next-hop/state
static int
oc_next_hop_state_cb(const char *xpath, sr_val_t **values, size_t *values_cnt,
                     uint64_t request_id, const char *original_xpath,
                     void *private_ctx)
{
    UNUSED(request_id); UNUSED(original_xpath); UNUSED(private_ctx);
    std::shared_ptr<route_dump> routes_fib = nullptr;
    vapi_type_ip_route route;
    sr_xpath_ctx_t state = {0};
    sr_val_t *vals = nullptr;
    string xprefix, xindex; //next hop index & prefix extracted from xpath
    int vc = 2;
    int cnt = 0;
    int rc;

    SRP_LOG_INF("In %s %s", __FUNCTION__, xpath);

    xprefix = sr_xpath_key_value((char*)xpath, "static", "prefix", &state);
    if (xprefix.empty()) {
        SRP_LOG_ERR("XPATH prefix NOT found", xpath);
        return SR_ERR_INVAL_ARG;
    }
    sr_xpath_recover(&state);
    xprefix.resize(xprefix.length() - 1);

    xindex = sr_xpath_key_value((char*)xpath, "next-hop", "index", &state);
    if (xindex.empty()) {
        SRP_LOG_ERR("XPATH prefix NOT found", xpath);
        return SR_ERR_INVAL_ARG;
    }
    sr_xpath_recover(&state);

    if (!sr_xpath_node_name_eq(xpath, "state"))
        return SR_ERR_INVAL_ARG;

    /* Perform the dump operation */
    routes_fib = std::make_shared<route_dump>(0, l3_proto_t::IPV4);
    HW::enqueue(routes_fib);
    HW::write();

    /* allocate array of values to be returned */
    rc = sr_new_values(vc, &vals);
    if (rc != 0)
        goto nothing_todo;

    for (auto &rt : *routes_fib) { //iterate over the result of the dump
        /* payload is a vapi ip_route */
        route = rt.get_payload().route;

        if (from_api(route.prefix).to_string() != xprefix)
            continue; //prefix not found, try next one

        // index is array number of vapi_type_ip_path, must be in [0, n_paths]
        if (stoi(xindex) < route.n_paths && stoi(xindex) > 0)
            continue;

        sr_val_build_xpath(&vals[cnt], "%s/index", xpath);
        sr_val_set_str_data(&vals[cnt], SR_STRING_T, xindex.c_str());
        cnt++;

        sr_val_build_xpath(&vals[cnt], "%s/next-hop", xpath);
        nh_proto_t proto = from_api(route.paths[stoi(xindex)].proto);
        if (proto == VOM::nh_proto_t::IPV4 || proto == VOM::nh_proto_t::IPV6) {
            string address = from_api(route.paths[stoi(xindex)].nh.address,
                                      route.paths[stoi(xindex)].proto)
                             .to_string();
            sr_val_set_str_data(&vals[cnt], SR_STRING_T, address.c_str());
        } else if (proto == VOM::nh_proto_t::ETHERNET) {
            string index = to_string(route.paths[stoi(xindex)].sw_if_index);
            sr_val_set_str_data(&vals[cnt], SR_STRING_T, index.c_str());
        } else {
            goto nothing_todo;
        }
        cnt++;

        break;
    }

    if (cnt == 0) //no matching prefix found
        goto nothing_todo;

    *values = vals;
    *values_cnt = cnt;

    return SR_ERR_OK;

nothing_todo:
    *values = NULL;
    *values_cnt = 0;
    return rc;
}

int
openconfig_local_routing_init(sc_plugin_main_t *pm)
{
    int rc = SR_ERR_OK;
    SRP_LOG_DBG_MSG("Initializing openconfig-local-routing plugin.");

    rc = sr_subtree_change_subscribe(pm->session, "/openconfig-local-routing:local-routes/static-routes/static/config",
            oc_static_config_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    //rc = sr_subtree_change_subscribe(pm->session, "/openconfig-local-routing:local-routes/static-routes/static/next-hops/next-hop/config",
    //        oc_next_hop_config_cb, NULL, 10, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    //if (SR_ERR_OK != rc) {
    //    goto error;
    //}

    rc = sr_dp_get_items_subscribe(pm->session, "/openconfig-local-routing:local-routes/static-routes/static/next-hops/next-hop/state",
            oc_next_hop_state_cb, NULL, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    SRP_LOG_DBG_MSG("openconfig-local-routing plugin initialized successfully.");
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("Error by initialization of openconfig-local-routing plugin. Error : %d", rc);
    return rc;
}

void
openconfig_local_routing_exit(__attribute__((unused)) sc_plugin_main_t *pm) {}

SC_INIT_FUNCTION(openconfig_local_routing_init);
SC_EXIT_FUNCTION(openconfig_local_routing_exit);
