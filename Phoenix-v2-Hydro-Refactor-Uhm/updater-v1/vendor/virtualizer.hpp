#pragma once

#ifdef USE_VIRTUALIZER
#include "vendor/oreans/include/VirtualizerSDK.h"
#define VL_VIRTUALIZATION_BEGIN VIRTUALIZER_START
#define VL_VIRTUALIZATION_END VIRTUALIZER_END
#else
#define VL_VIRTUALIZATION_BEGIN
#define VL_VIRTUALIZATION_END
#endif