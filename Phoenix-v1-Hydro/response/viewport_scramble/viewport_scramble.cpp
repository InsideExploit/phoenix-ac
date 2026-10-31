#include "viewport_scramble.hpp"
#include "vendor/lazy_importer.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>
#include <thread>
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

namespace response::viewport_scramble
{
    std::atomic<bool>     g_halt{ false };
    std::atomic<uint64_t> g_viewport{ 0 };
    std::atomic<DWORD>    g_pid{ 0 };

    namespace
    {
        enum method : uint32_t
        {
            m_random     = 0,
            m_identity,
            m_scale_big,
            m_flip_axes,
            m_full_noise,
            m_null_proj,
            m_swap_rows,
            m_negate,
            m_count
        };

        std::mt19937& rng()
        {
            thread_local std::mt19937 r{
                std::random_device{}() ^ static_cast<uint32_t>(LI_KERNEL(GetCurrentThreadId)())
            };
            return r;
        }

        void build_fake_matrix(uint8_t out[64])
        {
            float m[16] = { 0 };

            std::uniform_real_distribution<float> uni(-5.0f, 5.0f);
            std::uniform_real_distribution<float> big_scale(500.0f, 5000.0f);

            static const uint32_t weights[m_count] = { 4, 0, 5, 3, 5, 0, 3, 3 };
            uint32_t total = 0;
            for (uint32_t w : weights)
                total += w;

            std::uniform_int_distribution<uint32_t> pick(0, total - 1);
            const uint32_t r = pick(rng());

            uint32_t selected = 0;
            for (uint32_t i = 0, acc = 0; i < m_count; ++i)
            {
                acc += weights[i];
                if (r < acc)
                {
                    selected = i;
                    break;
                }
            }

            auto& gen = rng();

            switch (selected)
            {
            case m_random:
                for (int i = 0; i < 16; ++i)
                    m[i] = uni(gen);
                break;

            case m_identity:
                m[0] = m[5] = m[10] = m[15] = 1.0f;
                break;

            case m_scale_big:
            {
                const float s = big_scale(gen);
                m[0] = m[5] = m[10] = s;
                m[15] = 1.0f;
                break;
            }

            case m_flip_axes:
                m[0] = -1.0f; m[5] = -1.0f; m[10] = 1.0f; m[15] = 1.0f;
                m[3]  = uni(gen);
                m[7]  = uni(gen);
                m[11] = uni(gen);
                break;

            case m_full_noise:
                for (int i = 0; i < 16; ++i)
                    m[i] = uni(gen) * 2.5f;
                m[15] = 1.0f;
                break;

            case m_null_proj:
                m[15] = 1.0f;
                break;

            case m_swap_rows:
            {
                float id[16] = { 1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1 };
                int rows[4] = { 0, 1, 2, 3 };
                std::shuffle(std::begin(rows), std::end(rows), gen);
                for (int i = 0; i < 4; ++i)
                    for (int j = 0; j < 4; ++j)
                        m[i * 4 + j] = id[rows[i] * 4 + j];
                for (int j = 0; j < 4; ++j)
                    m[3 * 4 + j] += uni(gen) * 0.5f;
                break;
            }

            case m_negate:
                m[0] = -1.0f; m[5] = 1.0f; m[10] = -1.0f; m[15] = 1.0f;
                m[3]  = uni(gen) * 5.0f;
                m[7]  = uni(gen) * 5.0f;
                m[11] = uni(gen) * 5.0f;
                break;

            default:
                for (int i = 0; i < 16; ++i)
                    m[i] = uni(gen);
                break;
            }

            std::memcpy(out, m, 64);
        }

        struct tuning
        {
            int64_t corrupt_us;
            int64_t restore_us;
        };

        constexpr tuning k_tuning = { 500, 1 };

        HANDLE create_high_res_timer()
        {
            HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr,
                                                  CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                                  TIMER_ALL_ACCESS);
            if (!timer)
                timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
            return timer;
        }

        void micro_sleep(HANDLE timer, int64_t microseconds)
        {
            if (!timer || microseconds <= 0)
                return;

            LARGE_INTEGER due{};
            due.QuadPart = -(static_cast<LONGLONG>(microseconds) * 10);
            if (SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE))
                WaitForSingleObject(timer, INFINITE);
        }

        void scramble_thread()
        {
            SetThreadPriority(LI_KERNEL(GetCurrentThread)(), THREAD_PRIORITY_ABOVE_NORMAL);
            HANDLE timer = create_high_res_timer();

            HANDLE process = nullptr;
            DWORD owned_pid = 0;
            uint8_t original[64] = { 0 };
            uint8_t fake[64] = { 0 };
            uint64_t last_viewport = 0;
            bool original_valid = false;

            while (!g_halt.load())
            {
                const DWORD pid = g_pid.load();
                const uint64_t viewport = g_viewport.load();

                if (!pid || !viewport)
                {
                    if (process)
                    {
                        LI_KERNEL(CloseHandle)(process);
                        process = nullptr;
                        owned_pid = 0;
                    }
                    original_valid = false;
                    last_viewport = 0;
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }

                if (pid != owned_pid)
                {
                    if (process)
                        LI_KERNEL(CloseHandle)(process);
                    process = LI_KERNEL(OpenProcess)(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                          FALSE, pid);
                    owned_pid = process ? pid : 0;
                    original_valid = false;
                    last_viewport = 0;
                    if (!process)
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(200));
                        continue;
                    }
                }

                if (viewport != last_viewport || !original_valid)
                {
                    SIZE_T got = 0;
                    if (LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(viewport + 0x24C),
                                          original, 64, &got) && got == 64)
                    {
                        last_viewport = viewport;
                        original_valid = true;
                    }
                    else
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        continue;
                    }
                }

                build_fake_matrix(fake);

                SIZE_T written = 0;
                LI_KERNEL(WriteProcessMemory)(process, reinterpret_cast<LPVOID>(viewport + 0x24C),
                                   fake, 64, &written);
                micro_sleep(timer, k_tuning.corrupt_us);
                LI_KERNEL(WriteProcessMemory)(process, reinterpret_cast<LPVOID>(viewport + 0x24C),
                                   original, 64, &written);
                micro_sleep(timer, k_tuning.restore_us);
            }

            if (process && original_valid && last_viewport)
            {
                SIZE_T written = 0;
                LI_KERNEL(WriteProcessMemory)(process, reinterpret_cast<LPVOID>(last_viewport + 0x24C),
                                   original, 64, &written);
            }
            if (process)
                LI_KERNEL(CloseHandle)(process);
            if (timer)
                LI_KERNEL(CloseHandle)(timer);
        }
    }

    void start()
    {
        std::thread(scramble_thread).detach();
    }
}
