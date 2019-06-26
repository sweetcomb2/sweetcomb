/*
 * Copyright (c) 2018 HUACHENTEL and/or its affiliates.
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

#include "sc_plugins.h"

#include <dirent.h>

#include <vom/hw.hpp>
#include <vom/om.hpp>

static int vpp_pid_start;

sc_plugin_main_t sc_plugin_main;

using namespace VOM;

sc_plugin_main_t *sc_get_plugin_main()
{
    return &sc_plugin_main;
}

/* get vpp pid in system */
int get_vpp_pid()
{
    DIR *dir;
    struct dirent *ptr;
    FILE *fp;
    char filepath[50];
    char filetext[20];

    dir = opendir("/proc");
    int vpp_pid = 0;
    /* read vpp pid file in proc, return pid of vpp */
    if (NULL != dir)
    {
        while (NULL != (ptr =readdir(dir)))
        {
            if ((0 == strcmp(ptr->d_name, ".")) || (0 == strcmp(ptr->d_name, "..")))
                continue;

            if (DT_DIR != ptr->d_type)
                continue;

            sprintf(filepath, "/proc/%s/cmdline",ptr->d_name);
            fp = fopen(filepath, "r");

            if (NULL != fp)
            {
                fread(filetext, 1, 13, fp);
                filetext[12] = '\0';

                if (filetext == strstr(filetext, "/usr/bin/vpp"))
                    vpp_pid = atoi(ptr->d_name);

                fclose(fp);
            }
        }
        closedir(dir);
    }
    return vpp_pid;
}


int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    int rc;

    sc_plugin_main.session = session;

    /* Connection to VAPI via VOM and VOM database */
    HW::init();
    OM::init();
    while (HW::connect() != true);
    SRP_LOG_INF_MSG("Connection to VPP established");

    rc = sc_call_all_init_function(&sc_plugin_main);
    if (rc != SR_ERR_OK) {
        SRP_LOG_ERR("Call all init function error: %d", rc);
        return rc;
    }

    /* set subscription as our private context */
    *private_ctx = sc_plugin_main.subscription;

    /* Get initial PID of VPP process */
    vpp_pid_start = get_vpp_pid();

    return SR_ERR_OK;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    sc_call_all_exit_function(&sc_plugin_main);

    /* subscription was set as our private context */
    if (private_ctx != NULL)
        sr_unsubscribe(session, (sr_subscription_ctx_t*) private_ctx);
    SRP_LOG_DBG_MSG("unload plugin ok.");

    HW::disconnect();
    SRP_LOG_DBG_MSG("plugin disconnect vpp ok.");
}

int sr_plugin_health_check_cb(sr_session_ctx_t *session, void *private_ctx)
{
    int vpp_pid_now = get_vpp_pid();

    if (vpp_pid_now == vpp_pid_start)
        return SR_ERR_OK; //VPP has not crashed

    /* Wait until we succeed connecting to VPP */
    HW::disconnect();
    while (HW::connect() != true) {
        SRP_LOG_DBG_MSG("Try connecting to VPP again");
    };

    SRP_LOG_DBG_MSG("Connection to VPP established again");

    /* Though VPP has crashed, VOM database has kept the configuration.
     * This function replays the previous configuration to reconfigure VPP
     * so that VPP state matches sysrepo RUNNING DS and VOM database. */
    OM::replay();

    return SR_ERR_OK;
}
