/**
 * Copyright 2019-2020 DigitalOcean Inc.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <microhttpd.h>
#include "prom.h"

prom_collector_registry_t *PROM_ACTIVE_REGISTRY;

void promhttp_set_active_collector_registry(prom_collector_registry_t *active_registry) {
  if (!active_registry) {
    PROM_ACTIVE_REGISTRY = PROM_COLLECTOR_REGISTRY_DEFAULT;
  } else {
    PROM_ACTIVE_REGISTRY = active_registry;
  }
}

int promhttp_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                     const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
  char *password, *user;
  char *env_password = getenv("PROMETHEUS_BASIC_AUTH_PASSWORD");
  char *env_user = getenv("PROMETHEUS_BASIC_AUTH_USERNAME");
  int fail;
  struct MHD_Response *response;
  int ret;

  if (strcmp(method, "GET") != 0) {
    return MHD_NO;
  }

  password = NULL;
  user = MHD_basic_auth_get_username_password(connection, &password);

  fail = (!user || !password || !env_user || !env_password 
          || (env_user && strcmp(user, env_user)) || (env_password && strcmp(password, env_password)));

  if (user) 
    MHD_free(user);
  if (password) 
    MHD_free(password);

  if (fail) {
    const char *buf = "<html><body><h1>Unauthorized</h1></body></html>";
    response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_basic_auth_fail_response(connection, "realm", response);
  } else {
    if (strcmp(url, "/metrics") == 0) {
      const char *buf = prom_collector_registry_bridge(PROM_ACTIVE_REGISTRY);
      response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_MUST_FREE);
      ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    } else {
      const char *buf = "Bad Request\n";
      response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_PERSISTENT);
      ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
    }
  }
  MHD_destroy_response(response);
  return ret;
}

struct MHD_Daemon *promhttp_start_daemon(unsigned int flags, unsigned short port, MHD_AcceptPolicyCallback apc,
                                         void *apc_cls) {
  return MHD_start_daemon(flags, port, apc, apc_cls, &promhttp_handler, NULL, MHD_OPTION_END);
}

void promhttp_stop_daemon(struct MHD_Daemon *daemon){
    MHD_stop_daemon(daemon);
}