#pragma once

#include <string>

namespace security_check
{
    struct status
    {
        bool tpm20      = false;
        bool secure_boot = false;
        bool hvci       = false;
        bool dma_guard   = false;
        bool iommu      = false;

        bool all_ok() const
        {
            return tpm20 && secure_boot && hvci && dma_guard && iommu;
        }

        std::wstring missing_list() const;
    };

    status query();
}
