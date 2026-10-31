#pragma once

#include <Windows.h>
#include <winhttp.h>
#include <wincrypt.h>

namespace ssl_pinning
{
	bool traffic_interception_detected();
	bool verify(HINTERNET request);
}
