#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include <windows_emulator.hpp>

namespace sogen::ttd
{
    constexpr size_t default_keyframe_budget = size_t{1} << 30;
    // Keyframes are kept at multiples of this position: a seek keeps the last one before its target, preparing a trace
    // keeps all of them.
    constexpr uint64_t keyframe_interval = 25'000;

    // Replayed emulator states kept in memory, so that a seek restores the closest one instead of decoding a
    // checkpoint and replaying up to an interval. Guest memory is held as pages shared between keyframes; everything
    // else as the emulator's serialized state without memory contents. Safe to use from several threads.
    class keyframe_store
    {
      public:
        explicit keyframe_store(size_t memory_budget);

        keyframe_store(const keyframe_store&) = delete;
        keyframe_store& operator=(const keyframe_store&) = delete;

        // Keeps the emulator's state at its current position, then drops the least recently used keyframes beyond
        // the memory budget. `exact` tells that the replay reached it without substituting recorded inputs.
        void capture(const windows_emulator& win_emu, bool exact);
        // The same for an emulator that held keyframe `baseline`'s state and since changed guest memory only in
        // `written_pages` (sorted page addresses) and by mapping changes within `remapped` (address and size).
        void capture(const windows_emulator& win_emu, bool exact, uint64_t baseline, std::span<const uint64_t> written_pages,
                     std::span<const std::pair<uint64_t, uint64_t>> remapped);

        // Restores the latest keyframe from `first` to `last` (only exact ones with `exact_only`) and returns its
        // position and whether it is exact, if there is one.
        std::optional<std::pair<uint64_t, bool>> restore_latest(windows_emulator& win_emu, uint64_t first, uint64_t last, bool exact_only);

        // Notes that the emulator holds keyframe `baseline`'s state changed only in `written_pages` (sorted page
        // addresses) and by mapping changes within `remapped`. The next restore into it then writes only the pages
        // that can differ, unless anything changed the emulator's memory in between.
        void note_state(const windows_emulator& win_emu, uint64_t baseline, std::vector<uint64_t> written_pages,
                        std::vector<std::pair<uint64_t, uint64_t>> remapped);

        size_t memory_usage() const;
        size_t size() const;
        size_t memory_budget() const;
        void set_memory_budget(size_t memory_budget);

      private:
        static constexpr size_t page_size = 0x1000;
        static constexpr uint32_t zero_page = UINT32_MAX;

        struct page
        {
            std::array<std::byte, page_size> bytes{};
            uint64_t hash{};
            uint32_t references{};
        };

        struct region
        {
            uint64_t address{};
            size_t length{};
            std::vector<uint32_t> pages{};
        };

        using objects_reference = std::shared_ptr<const std::vector<std::byte>>;

        struct keyframe
        {
            // Compressed against `reference`, the uncompressed objects of an earlier keyframe.
            std::vector<std::byte> objects{};
            objects_reference reference{};
            std::vector<region> regions{};
            uint64_t last_use{};
            bool exact{};
        };

        struct known_state
        {
            uint64_t memory_generation{};
            uint64_t baseline{};
            std::vector<uint64_t> written_pages{};
            // Sorted, disjoint [begin, end) ranges.
            std::vector<std::pair<uint64_t, uint64_t>> remapped{};
        };

        mutable std::mutex mutex_{};
        std::unordered_map<const windows_emulator*, known_state> known_states_{};
        size_t memory_budget_{};
        uint64_t use_counter_{};
        std::map<uint64_t, keyframe> keyframes_{};
        std::vector<std::unique_ptr<page>> pages_{};
        std::vector<uint32_t> free_pages_{};
        std::unordered_multimap<uint64_t, uint32_t> pages_by_hash_{};
        size_t objects_bytes_{};
        // Keyframes per reference, and the size of all references in use.
        std::unordered_map<const std::vector<std::byte>*, size_t> reference_users_{};
        size_t references_bytes_{};
        std::vector<std::byte> objects_buffer_{};

        void capture(const windows_emulator& win_emu, bool exact, std::optional<uint64_t> baseline, std::span<const uint64_t> written_pages,
                     std::span<const std::pair<uint64_t, uint64_t>> remapped);
        size_t memory_usage_locked() const;
        // The page keyframe `frame` holds at `page_address`, if that address is committed in it.
        static std::optional<uint32_t> page_at(const keyframe& frame, uint64_t page_address);
        // Whether page `id` holds `bytes` (zero-padded to a page).
        bool holds(uint32_t id, std::span<const std::byte> bytes) const;
        uint32_t intern(std::span<const std::byte> bytes);
        void release(uint32_t id);
        void release(const keyframe& frame);
        void enforce_budget(uint64_t keep);
    };
}
