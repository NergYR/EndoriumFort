#pragma once

#include "security_middleware.h"

struct AppContext;

void register_cluster_routes(CrowApp &app, AppContext &ctx);
