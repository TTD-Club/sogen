#include "ttd_keyframes.hpp"

#include <utils/compression.hpp>

#include <algorithm>
#include <cstring>
#include <ranges>
#include <stdexcept>

#define XXH_INLINE_ALL
#include <common/xxhash.h>

namespace sogen::ttd
{
    keyframe_store::keyframe_store(const size_t memory_budget)
        : memory_budget_(memory_budget)
    {
    }

    size_t keyframe_store::size() const
    {
        const std::scoped_lock lock{this->mutex_};
        return this->keyframes_.size();
    }

    size_t keyframe_store::memory_budget() const
    {
        const std::scoped_lock lock{this->mutex_};
        return this->memory_budget_;
    }

    void keyframe_store::set_memory_budget(const size_t memory_budget)
    {
        const std::scoped_lock lock{this->mutex_};
        this->memory_budget_ = memory_budget;
        this->enforce_budget(UINT64_MAX);
    }

    void keyframe_store::capture(const windows_emulator& win_emu, const bool exact)
    {
        this->capture(win_emu, exact, std::nullopt, {}, {});
    }

    void keyframe_store::capture(const windows_emulator& win_emu, const bool exact, const uint64_t baseline,
                                 const std::span<const uint64_t> written_pages,
                                 const std::span<const std::pair<uint64_t, uint64_t>> remapped)
    {
        this->capture(win_emu, exact, std::optional{baseline}, written_pages, remapped);
    }

    void keyframe_store::capture(const windows_emulator& win_emu, const bool exact, const std::optional<uint64_t> baseline_position,
                                 const std::span<const uint64_t> written_pages,
                                 const std::span<const std::pair<uint64_t, uint64_t>> remapped)
    {
        const auto position = win_emu.get_executed_instructions();
        const auto existing_suffices = [&] {
            const auto existing = this->keyframes_.find(position);
            if (existing == this->keyframes_.end())
            {
                return false;
            }
            existing->second.last_use = ++this->use_counter_;
            if (existing->second.exact || !exact)
            {
                return true;
            }
            this->release(existing->second);
            this->keyframes_.erase(existing);
            return false;
        };
        {
            const std::scoped_lock lock{this->mutex_};
            if (!this->memory_budget_ || existing_suffices())
            {
                return;
            }
        }

        keyframe frame{};
        utils::buffer_serializer serializer{};
        win_emu.serialize_without_memory_contents(serializer);
        const auto& objects = serializer.get_buffer();

        // Keyframes mostly share their objects (module symbols above all), so each is stored as a delta against the
        // objects of an earlier keyframe of the same stretch of the run: its baseline's reference, or the nearest
        // keyframe's. A keyframe whose delta grows large becomes a reference itself.
        {
            const std::scoped_lock lock{this->mutex_};
            const auto baseline = baseline_position ? this->keyframes_.find(*baseline_position) : this->keyframes_.end();
            if (baseline != this->keyframes_.end())
            {
                frame.reference = baseline->second.reference;
            }
            else if (!this->keyframes_.empty())
            {
                auto nearest = this->keyframes_.upper_bound(position);
                frame.reference = (nearest == this->keyframes_.begin() ? nearest : std::prev(nearest))->second.reference;
            }
        }
        if (frame.reference)
        {
            frame.objects = utils::compression::zstd::compress_with_reference(objects, *frame.reference, 1);
        }
        if (!frame.reference || frame.objects.size() > objects.size() / 32)
        {
            frame.reference = std::make_shared<const std::vector<std::byte>>(objects);
            frame.objects = utils::compression::zstd::compress_with_reference(objects, *frame.reference, 1);
        }

        const std::scoped_lock lock{this->mutex_};
        const keyframe* baseline = nullptr;
        if (baseline_position)
        {
            if (const auto found = this->keyframes_.find(*baseline_position); found != this->keyframes_.end())
            {
                baseline = &found->second;
            }
        }

        const auto same_region = [](const keyframe* frame, const uint64_t address, const size_t length) -> const region* {
            if (!frame)
            {
                return nullptr;
            }
            const auto found = std::ranges::lower_bound(frame->regions, address, {}, &region::address);
            return found != frame->regions.end() && found->address == address && found->length == length ? &*found : nullptr;
        };
        const auto unchanged_since_baseline = [&](const uint64_t address, const size_t length) -> const region* {
            const auto touched = std::ranges::any_of(
                remapped, [&](const auto& range) { return range.first < address + length && address < range.first + range.second; });
            return touched ? nullptr : same_region(baseline, address, length);
        };

        // Without a baseline, pages are first compared with the nearest keyframe's, which is much cheaper than hashing.
        const keyframe* nearest = nullptr;
        if (!baseline && !this->keyframes_.empty())
        {
            auto candidate = this->keyframes_.upper_bound(position);
            if (candidate != this->keyframes_.begin())
            {
                --candidate;
            }
            nearest = &candidate->second;
        }

        std::vector<std::byte> contents{};
        for (const auto& reserved : win_emu.memory.get_reserved_regions() | std::views::values)
        {
            if (reserved.kind == memory_region_kind::mmio)
            {
                continue;
            }
            for (const auto& [address, committed] : reserved.committed_regions)
            {
                region captured{.address = address, .length = committed.length};
                if (const auto* earlier = unchanged_since_baseline(address, committed.length))
                {
                    captured.pages = earlier->pages;
                    for (const auto id : captured.pages)
                    {
                        if (id != zero_page)
                        {
                            ++this->pages_[id]->references;
                        }
                    }
                    for (auto page = std::ranges::lower_bound(written_pages, address);
                         page != written_pages.end() && *page < address + committed.length; ++page)
                    {
                        const auto index = static_cast<size_t>((*page - address) / page_size);
                        contents.resize(std::min(page_size, committed.length - (index * page_size)));
                        win_emu.memory.read_memory(*page, contents.data(), contents.size());
                        const auto id = this->intern(contents);
                        this->release(captured.pages[index]);
                        captured.pages[index] = id;
                    }
                    frame.regions.push_back(std::move(captured));
                    continue;
                }

                contents.resize(committed.length);
                win_emu.memory.read_memory(address, contents.data(), contents.size());
                const auto* similar = same_region(nearest, address, committed.length);
                captured.pages.reserve((committed.length + page_size - 1) / page_size);
                for (size_t offset = 0; offset < committed.length; offset += page_size)
                {
                    const auto bytes = std::span(contents).subspan(offset, std::min(page_size, committed.length - offset));
                    if (similar)
                    {
                        if (const auto id = similar->pages[offset / page_size]; this->holds(id, bytes))
                        {
                            if (id != zero_page)
                            {
                                ++this->pages_[id]->references;
                            }
                            captured.pages.push_back(id);
                            continue;
                        }
                    }
                    captured.pages.push_back(this->intern(bytes));
                }
                frame.regions.push_back(std::move(captured));
            }
        }

        frame.last_use = ++this->use_counter_;
        frame.exact = exact;
        this->objects_bytes_ += frame.objects.size();
        if (++this->reference_users_[frame.reference.get()] == 1)
        {
            this->references_bytes_ += frame.reference->size();
        }
        if (existing_suffices())
        {
            this->release(frame);
            return;
        }
        this->keyframes_.emplace(position, std::move(frame));
        this->enforce_budget(position);
    }

    std::optional<std::pair<uint64_t, bool>> keyframe_store::restore_latest(windows_emulator& win_emu, const uint64_t first,
                                                                            const uint64_t last, const bool exact_only)
    {
        const std::scoped_lock lock{this->mutex_};
        auto candidate = this->keyframes_.upper_bound(last);
        while (candidate != this->keyframes_.begin() && std::prev(candidate)->first >= first && exact_only &&
               !std::prev(candidate)->second.exact)
        {
            --candidate;
        }
        if (candidate == this->keyframes_.begin() || std::prev(candidate)->first < first)
        {
            return std::nullopt;
        }
        const auto position = std::prev(candidate)->first;
        auto& frame = std::prev(candidate)->second;
        frame.last_use = ++this->use_counter_;

        // A page the emulator is known to hold already needs neither a comparison nor a write.
        const keyframe* known_frame = nullptr;
        known_state known{};
        if (auto entry = this->known_states_.extract(&win_emu))
        {
            known = std::move(entry.mapped());
            const auto baseline = this->keyframes_.find(known.baseline);
            if (baseline != this->keyframes_.end() && win_emu.emu().get_memory_generation() == known.memory_generation)
            {
                known_frame = &baseline->second;
            }
        }
        const auto holds_already = [&](const uint64_t page_address, const uint32_t id) {
            if (!known_frame || std::ranges::binary_search(known.written_pages, page_address))
            {
                return false;
            }
            const auto remap = std::ranges::upper_bound(known.remapped, page_address, {}, &std::pair<uint64_t, uint64_t>::first);
            if (remap != known.remapped.begin() && page_address < std::prev(remap)->second)
            {
                return false;
            }
            if (remap != known.remapped.end() && remap->first < page_address + page_size)
            {
                return false;
            }
            const auto known_id = page_at(*known_frame, page_address);
            return known_id && *known_id == id;
        };

        if (!utils::compression::zstd::decompress_with_reference(frame.objects, *frame.reference, this->objects_buffer_))
        {
            throw std::runtime_error("Cannot decompress a TTD keyframe");
        }
        utils::buffer_deserializer deserializer{this->objects_buffer_};
        win_emu.deserialize_without_memory_contents(deserializer, [&](const uint64_t page_address) {
            const auto id = page_at(frame, page_address);
            if (!id)
            {
                throw std::runtime_error("TTD keyframe has no contents for a committed page");
            }
            return restored_page{.data = *id == zero_page ? nullptr : this->pages_[*id]->bytes.data(),
                                 .unchanged = holds_already(page_address, *id)};
        });
        return std::pair{position, frame.exact};
    }

    void keyframe_store::note_state(const windows_emulator& win_emu, const uint64_t baseline, std::vector<uint64_t> written_pages,
                                    std::vector<std::pair<uint64_t, uint64_t>> remapped)
    {
        const auto generation = win_emu.emu().get_memory_generation();
        const std::scoped_lock lock{this->mutex_};
        if (!generation)
        {
            this->known_states_.erase(&win_emu);
            return;
        }

        for (auto& [address, end] : remapped)
        {
            end += address;
        }
        std::ranges::sort(remapped);
        std::vector<std::pair<uint64_t, uint64_t>> merged{};
        merged.reserve(remapped.size());
        for (const auto& range : remapped)
        {
            if (!merged.empty() && range.first <= merged.back().second)
            {
                merged.back().second = std::max(merged.back().second, range.second);
            }
            else
            {
                merged.push_back(range);
            }
        }

        this->known_states_[&win_emu] = {.memory_generation = *generation,
                                         .baseline = baseline,
                                         .written_pages = std::move(written_pages),
                                         .remapped = std::move(merged)};
    }

    std::optional<uint32_t> keyframe_store::page_at(const keyframe& frame, const uint64_t page_address)
    {
        const auto next = std::ranges::upper_bound(frame.regions, page_address, {}, &region::address);
        if (next == frame.regions.begin())
        {
            return std::nullopt;
        }
        const auto& owner = *std::prev(next);
        const auto index = static_cast<size_t>((page_address - owner.address) / page_size);
        if (index >= owner.pages.size())
        {
            return std::nullopt;
        }
        return owner.pages[index];
    }

    size_t keyframe_store::memory_usage() const
    {
        const std::scoped_lock lock{this->mutex_};
        return this->memory_usage_locked();
    }

    size_t keyframe_store::memory_usage_locked() const
    {
        return ((this->pages_.size() - this->free_pages_.size()) * sizeof(page)) + this->objects_bytes_ + this->references_bytes_;
    }

    bool keyframe_store::holds(const uint32_t id, const std::span<const std::byte> bytes) const
    {
        const auto is_zero = [](const std::byte value) { return value == std::byte{0}; };
        if (id == zero_page)
        {
            return std::ranges::all_of(bytes, is_zero);
        }
        const auto& stored = this->pages_[id]->bytes;
        return std::memcmp(stored.data(), bytes.data(), bytes.size()) == 0 &&
               std::all_of(stored.begin() + static_cast<ptrdiff_t>(bytes.size()), stored.end(), is_zero);
    }

    uint32_t keyframe_store::intern(const std::span<const std::byte> bytes)
    {
        if (this->holds(zero_page, bytes))
        {
            return zero_page;
        }

        const auto hash = XXH64(bytes.data(), bytes.size(), 0);
        const auto [first, last] = this->pages_by_hash_.equal_range(hash);
        for (auto candidate = first; candidate != last; ++candidate)
        {
            if (this->holds(candidate->second, bytes))
            {
                ++this->pages_[candidate->second]->references;
                return candidate->second;
            }
        }

        auto stored = std::make_unique<page>();
        std::ranges::copy(bytes, stored->bytes.begin());
        stored->hash = hash;
        stored->references = 1;

        uint32_t id{};
        if (this->free_pages_.empty())
        {
            id = static_cast<uint32_t>(this->pages_.size());
            this->pages_.push_back(std::move(stored));
        }
        else
        {
            id = this->free_pages_.back();
            this->free_pages_.pop_back();
            this->pages_[id] = std::move(stored);
        }
        this->pages_by_hash_.emplace(hash, id);
        return id;
    }

    void keyframe_store::release(const uint32_t id)
    {
        if (id == zero_page || --this->pages_[id]->references)
        {
            return;
        }
        const auto [first, last] = this->pages_by_hash_.equal_range(this->pages_[id]->hash);
        for (auto candidate = first; candidate != last; ++candidate)
        {
            if (candidate->second == id)
            {
                this->pages_by_hash_.erase(candidate);
                break;
            }
        }
        this->pages_[id].reset();
        this->free_pages_.push_back(id);
    }

    void keyframe_store::release(const keyframe& frame)
    {
        for (const auto& owner : frame.regions)
        {
            for (const auto id : owner.pages)
            {
                this->release(id);
            }
        }
        this->objects_bytes_ -= frame.objects.size();
        if (const auto users = this->reference_users_.find(frame.reference.get());
            users != this->reference_users_.end() && !--users->second)
        {
            this->references_bytes_ -= frame.reference->size();
            this->reference_users_.erase(users);
        }
    }

    void keyframe_store::enforce_budget(const uint64_t keep)
    {
        while (this->memory_usage_locked() > this->memory_budget_)
        {
            auto oldest = this->keyframes_.end();
            for (auto candidate = this->keyframes_.begin(); candidate != this->keyframes_.end(); ++candidate)
            {
                if (candidate->first != keep && (oldest == this->keyframes_.end() || candidate->second.last_use < oldest->second.last_use))
                {
                    oldest = candidate;
                }
            }
            if (oldest == this->keyframes_.end())
            {
                break;
            }
            this->release(oldest->second);
            this->keyframes_.erase(oldest);
        }
    }
}
