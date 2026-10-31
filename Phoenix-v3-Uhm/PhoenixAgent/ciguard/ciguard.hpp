#pragma once
#include <windows.h>

enum KG_CI_STATE {
    KgCiStateOk           = 0,
    KgCiStateEnforcement  = 1,
    KgCiStateEvaluation   = 2,
};

KG_CI_STATE
CiGuardCheckState(
);

bool
CiGuardSecureBootEnabled(
);

bool
CiGuardDeletePolicies(
);
