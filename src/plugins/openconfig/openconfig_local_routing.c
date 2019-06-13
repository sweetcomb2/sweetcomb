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
#include <string.h>

#include <vom/om.hpp>
#include <vom/interface.hpp>
#include "vom/prefix.hpp"
#include "vom/route.hpp"
#include "vom/route_cmds.hpp"

#include <string>
#include <map>
#include <exception>

#include "sc_plugins.h"

using namespace boost;
using namespace std;
using namespace VOM;

struct pathNode {
    int index;
    bool is_add;
    string path;
    string intf;
    pathNode *next;
};

struct infoPaths {
    pathNode *pathList;
    pathNode *lastPath;
};

struct keyRoute {
    string prefix;

    keyRoute(const string key) : prefix(key) {}
    bool operator<(const keyRoute& key) const { 
        return (prefix.compare(key.prefix)<0);
    }
};

typedef map<keyRoute, infoPaths> TMapRoutes;
TMapRoutes mapOfRoutes;

/* @brief add/del route to FIB table 0.
 */
static inline int
set_route(const string uuid, const char *prefix, pathNode *pathList)
{
    int prefix_len;

    // Put prefix length in mask and prefix IP in prefix
    prefix_len = ip_prefix_split(prefix);
    if (prefix_len < 1) {
        SRP_LOG_ERR("Prefix length can not be %d", prefix_len);
        return SR_ERR_INVAL_ARG;
    }

    try {
        route::prefix_t pfx(prefix, prefix_len);
        route::ip_route rt(pfx);

        pathNode *node = pathList;
        do {
            boost::asio::ip::address nh = boost::asio::ip::address::from_string(node->path.c_str());
            route::path path(0, nh);
            (node->is_add) ? rt.add(path) : rt.remove(path);
            OM::write(uuid, rt);
            SRP_LOG_DBG("OM::WRITE ... %s", uuid.c_str());
            node = node->next;
        } while ( node != 0);
    } catch (std::exception &exc) {
        // catch boost exception from prefix_t
        SRP_LOG_ERR("Error: %s", exc.what());
        return SR_ERR_OPERATION_FAILED;
    }

    return SR_ERR_OK;
}

// XPATH: /openconfig-local-routing:local-routes/static-routes/static[prefix='%s']/next-hops/next-hop[index='%s']/config/
static int oc_next_hop_config_cb(sr_session_ctx_t *ds, const char *xpath,
                                 sr_notif_event_t event, void *private_ctx)
{
    sr_change_iter_t *it;
    sr_change_oper_t oper;
    sr_val_t *old_val, *new_val, *tmp;
    sr_xpath_ctx_t state = {0};
    int rc = SR_ERR_OK;
    UNUSED(private_ctx);

    string prefix, next_hop, interface, ind;
    int index;

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

        prefix = sr_xpath_key_value(tmp->xpath, "static", "prefix", &state);
        sr_xpath_recover(&state);
        prefix.resize(prefix.length()-1);

        // parse request
        keyRoute key_route(prefix);
        TMapRoutes::iterator vIter = mapOfRoutes.find(key_route);
        if (sr_xpath_node_name_eq(tmp->xpath, "next-hop")) {
            ind = sr_xpath_key_value(tmp->xpath, "next-hop", "index", &state);
            sr_xpath_recover(&state);
            index = atoi(ind.c_str());

            next_hop = tmp->data.string_val;
            // remove ending '$'
            next_hop.resize(next_hop.length()-1);
            if (vIter == mapOfRoutes.end())
            {
                infoPaths paths;
                paths.pathList = new pathNode;
                paths.lastPath = paths.pathList;
                paths.lastPath->index = index;
                paths.lastPath->path = next_hop;
                paths.lastPath->next = 0;
                paths.lastPath->is_add = (oper == SR_OP_CREATED);
                mapOfRoutes.insert(TMapRoutes::value_type(key_route, paths));
            } else {
                infoPaths paths = vIter->second;
                paths.pathList->next = new pathNode;
                paths.lastPath = paths.pathList->next;
                paths.lastPath->index = index;
                paths.lastPath->path = next_hop;
                paths.lastPath->next = 0;
                paths.lastPath->is_add = (oper == SR_OP_CREATED);
            }
        }

        sr_free_val(old_val);
        sr_free_val(new_val);
        sr_xpath_recover(&state);
    }

    // create/modify/delete routes
    for (const auto &entry: mapOfRoutes)
    {
        string uuid = string(xpath) + "/" + entry.first.prefix + "/";
        OM::mark_n_sweep ms(uuid);
        SRP_LOG_DBG("OM::MS ... %s", uuid.c_str());

        rc = set_route(uuid,
                       entry.first.prefix.c_str(),
                       entry.second.pathList);
    }
    // cleanup mapOfRoutes
    for (const auto &entry: mapOfRoutes)
    {
        pathNode *node = entry.second.pathList, *next;
        while (node != nullptr) {
            next = node->next;
            delete node;
            node = next;
        }
    }
    mapOfRoutes.clear();

    sr_free_change_iter(it);
    return rc;
}

#define NUM_VALS_STATE_STATIC_ROUTE 1
#define NUM_VALS_STATE_NEXT_HOP     2

// XPATH: /openconfig-local-routing:local-routes/static-routes/static/state
static int oc_prefix_state_cb(
    const char *xpath, sr_val_t **values, size_t *values_cnt,
    uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    UNUSED(request_id); UNUSED(original_xpath); UNUSED(private_ctx);
    sr_val_t *vals = nullptr;
    sr_xpath_ctx_t state = {0};
    int cnt = 0;

    *values = nullptr;
    *values_cnt = 0;

    string req_prefix = sr_xpath_key_value((char*)xpath, "static", "prefix", &state);
    req_prefix.resize(req_prefix.length()-1);
    if (req_prefix.empty()) {
        SRP_LOG_ERR("XPATH prefix NOT found", xpath);
        return SR_ERR_INVAL_ARG;
    }
    sr_xpath_recover(&state);

    if (!sr_xpath_node_name_eq(xpath, "state"))
        return SR_ERR_INVAL_ARG;

    SRP_LOG_INF("In %s %s", __FUNCTION__, xpath);

    /* allocate array of values to be returned */
    if (0 != sr_new_values(NUM_VALS_STATE_STATIC_ROUTE, &vals))
        return SR_ERR_OPERATION_FAILED;

    char prefix[INET6_ADDRSTRLEN+5];
    if (req_prefix.find(":") == string::npos) {
        std::shared_ptr<route::ip_route_cmds::dump_v4_cmd> routes_fib4 =
            std::make_shared<route::ip_route_cmds::dump_v4_cmd>();
        HW::enqueue(routes_fib4);
        HW::write();

        for (auto& rt : *routes_fib4) {
            vapi_payload_ip_fib_details payload = rt.get_payload();
            if (sc_ntop(AF_INET, payload.address, prefix)) {
                strcat(prefix,"/");
                strcat(prefix, to_string((int)payload.address_length).c_str());
                if (!req_prefix.compare(prefix)) {
                    strcat(prefix, "$");
                    sr_val_build_xpath(&vals[cnt], "%s/prefix", xpath);
                    sr_val_set_str_data(&vals[cnt++], SR_STRING_T, prefix);
                    break;
                }
            }
        }
    } else {
        std::shared_ptr<route::ip_route_cmds::dump_v6_cmd> routes_fib6 =
            std::make_shared<route::ip_route_cmds::dump_v6_cmd>();
        HW::enqueue(routes_fib6);
        HW::write();
        for (auto& rt : *routes_fib6) {
            vapi_payload_ip6_fib_details payload = rt.get_payload();
            if (sc_ntop(AF_INET6, payload.address, prefix)) {
                strcat(prefix,"/");
                strcat(prefix, to_string((int)payload.address_length).c_str());
                if (!req_prefix.compare(prefix)) {
                    strcat(prefix, "$");
                    sr_val_build_xpath(&vals[cnt], "%s/prefix", xpath);
                    sr_val_set_str_data(&vals[cnt++], SR_STRING_T, prefix);
                    break;
                }
            }
        }
    }
    *values = vals;
    *values_cnt = cnt;

    return SR_ERR_OK;
}

// XPATH /openconfig-local-routing:local-routes/static-routes/static/next-hops/next-hop/state
static int
oc_next_hop_state_cb(const char *xpath, sr_val_t **values, size_t *values_cnt,
                     uint64_t request_id, const char *original_xpath,
                     void *private_ctx)
{
    UNUSED(request_id); UNUSED(original_xpath); UNUSED(private_ctx);
    sr_xpath_ctx_t state = {0};
    sr_val_t *vals = nullptr;
    int cnt = 0, index;

    *values = nullptr;
    *values_cnt = 0;

    string req_prefix = sr_xpath_key_value((char*)xpath, "static", "prefix", &state);
    req_prefix.resize(req_prefix.length()-1);
    if (req_prefix.empty()) {
        SRP_LOG_ERR("XPATH prefix NOT found", xpath);
        return SR_ERR_INVAL_ARG;
    }
    sr_xpath_recover(&state);

    string req_index = sr_xpath_key_value((char*)xpath, "next-hop", "index", &state);
    sr_xpath_recover(&state);

    if (!sr_xpath_node_name_eq(xpath, "state"))
        return SR_ERR_INVAL_ARG;

    SRP_LOG_INF("In %s %s", __FUNCTION__, xpath);

    /* allocate array of values to be returned */
    if (0 != sr_new_values(NUM_VALS_STATE_NEXT_HOP, &vals))
        return SR_ERR_OPERATION_FAILED;

    char prefix[INET6_ADDRSTRLEN+1];
    char next_hop[INET6_ADDRSTRLEN+1];
    if (req_prefix.find(":") == string::npos) {
        std::shared_ptr<route::ip_route_cmds::dump_v4_cmd> routes_fib4 =
            std::make_shared<route::ip_route_cmds::dump_v4_cmd>();
        HW::enqueue(routes_fib4);
        HW::write();

        for (auto &rt : *routes_fib4) {
            vapi_payload_ip_fib_details payload = rt.get_payload();
            if (sc_ntop(AF_INET, payload.address, prefix)) {
                strcat(prefix,"/");
                strcat(prefix, to_string((int)payload.address_length).c_str());
                index = atoi(req_index.c_str());
                if (!req_prefix.compare(prefix) &&
                    index>-1 && index<payload.count) {
                    if (sc_ntop(AF_INET, payload.path[index].next_hop, next_hop)) {
                        strcat(next_hop, "$");
                        sr_val_build_xpath(&vals[cnt], "%s/index", xpath);
                        sr_val_set_str_data(&vals[cnt++], SR_STRING_T, req_index.c_str());
                        sr_val_build_xpath(&vals[cnt], "%s/next-hop", xpath);
                        sr_val_set_str_data(&vals[cnt++], SR_STRING_T, next_hop);
                    }
                }
            }
        }
    } else {
        std::shared_ptr<route::ip_route_cmds::dump_v6_cmd> routes_fib6 =
            std::make_shared<route::ip_route_cmds::dump_v6_cmd>();
        HW::enqueue(routes_fib6);
        HW::write();

        for (auto &rt : *routes_fib6) {
            vapi_payload_ip6_fib_details payload = rt.get_payload();
            if (sc_ntop(AF_INET6, payload.address, prefix)) {
                strcat(prefix,"/");
                strcat(prefix, to_string((int)payload.address_length).c_str());
                index = atoi(req_index.c_str());
                if (!req_prefix.compare(prefix) &&
                    index>-1 && index<payload.count) {
                    if (sc_ntop(AF_INET6, payload.path[index].next_hop, next_hop)) {
                        strcat(next_hop, "$");
                        sr_val_build_xpath(&vals[cnt], "%s/index", xpath);
                        sr_val_set_str_data(&vals[cnt++], SR_STRING_T, req_index.c_str());
                        sr_val_build_xpath(&vals[cnt], "%s/next-hop", xpath);
                        sr_val_set_str_data(&vals[cnt++], SR_STRING_T, next_hop);
                    }
                }
            }
        }
    }
    *values = vals;
    *values_cnt = cnt;
    return SR_ERR_OK;
}

int
openconfig_local_routing_init(sc_plugin_main_t *pm)
{
    int rc = SR_ERR_OK;
    SRP_LOG_DBG_MSG("Initializing openconfig-local-routing plugin.");

    rc = sr_subtree_change_subscribe(pm->session, "/openconfig-local-routing:local-routes/static-routes/static/config",
            oc_next_hop_config_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/openconfig-local-routing:local-routes/static-routes/static/next-hops/next-hop/config",
            oc_next_hop_config_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(pm->session, "/openconfig-local-routing:local-routes/static-routes/static/state",
            oc_prefix_state_cb, NULL, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

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