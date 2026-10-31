#pragma once

#include <ntifs.h>

DRIVER_DISPATCH DispatchCreate;
DRIVER_DISPATCH DispatchClose;
DRIVER_DISPATCH DispatchRead;
DRIVER_DISPATCH DispatchGeneric;
DRIVER_DISPATCH DispatchDeviceControl;
