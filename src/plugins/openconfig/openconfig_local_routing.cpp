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
    boost::asio::ip::address nh;

    // Put prefix length in mask and prefix IP in prefix
    utils::prefix p(prefix);

    try {
        route::prefix_t vompfx(p.address(), p.prefix_length());
        route::ip_route rt(vompfx);

        pathNode *node = pathList;
        do {
            nh = boost::asio::ip::address::from_string(node->path.c_str());
            route::path path(0, nh);
            (node->is_add) ? rt.add(path) : rt.remove(path);
            OM::write(uuid, rt);
            SRP_LOG_DBG("OM::WRITE ... %s", uuid.c_str());
            node = node->next;
        } while (node != 0);
    } catch (std::exception &exc) { // catch boost exception from prefix_t
        SRP_LOG_ERR("Error: %s", exc.what());
        return SR_ERR_OPERATION_FAILED;
    }

    return SR_ERR_OK;
}

// XPATH: /openconfig-local-routing:local-routes/static-routes/static[prefix='%s']/next-hops/next-hop[index='%s']/config/
static int
oc_next_hop_config_cb(sr_session_ctx_t *ds, const char *xpath,
                      sr_notif_event_t event, void *private_ctx)
{
    sr_change_iter_t *it;
    sr_change_oper_t oper;
    sr_val_t *old_val, *new_val, *tmp;
    sr_xpath_ctx_t state = {0};
    UNUSED(private_ctx);
    string prefix, next_hop, interface, ind;
    int index;
    int rc = SR_ERR_OK;

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
        if (prefix.empty()) {
            SRP_LOG_ERR("XPATH prefix NOT found", xpath);
            return SR_ERR_INVAL_ARG;
        }
        sr_xpath_recover(&state);
        prefix.resize(prefix.length() - 1);

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
            oc_next_hop_config_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &pm->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_subtree_change_subscribe(pm->session, "/openconfig-local-routing:local-routes/static-routes/static/next-hops/next-hop/config",
            oc_next_hop_config_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &pm->subscription);
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
