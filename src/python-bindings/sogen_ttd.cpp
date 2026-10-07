#include <nanobind/nanobind.h>

#include "sogen_internal.hpp"

#include <ttd_buffer_scan.hpp>
#include <ttd_session.hpp>
#include <ttd_string_scan.hpp>
#include <ttd_trace.hpp>

#include <sstream>

namespace sogen::py
{
    namespace
    {
        using ttd::access_kind;

        nb::bytes to_bytes(const std::span<const std::byte> data)
        {
            return nb::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }

        struct ttd_event
        {
            uint64_t position{};
            uint64_t ip{};
            uint64_t address{};
            uint64_t size{};
            access_kind kind{};
            // Bytes read or written, or for an execute the instruction bytes.
            std::vector<std::byte> data{};

            std::string repr() const
            {
                std::ostringstream text;
                text << std::hex << "Event(position=0x" << this->position << ", kind=" << ttd::access_kind_name(this->kind) << ", ip=0x"
                     << this->ip << ", address=0x" << this->address << ", size=" << std::dec << this->size << ")";
                return text.str();
            }
        };

        struct ttd_history_entry
        {
            ttd_event event{};
            // The range's bytes after the event; None for bytes no access has shown yet.
            std::vector<std::optional<uint8_t>> value{};
        };

        class ttd_trace
        {
          public:
            explicit ttd_trace(const std::filesystem::path& path)
                : trace_(std::make_shared<ttd::trace>(path))
            {
            }

            ttd::trace& native() const
            {
                if (!this->trace_)
                {
                    throw std::runtime_error("TTD trace is closed");
                }
                return *this->trace_;
            }

            // The file stays open while a replay or an event iterator of this trace exists.
            void close()
            {
                this->trace_.reset();
            }

            ttd_event event(const ttd::access_event& event) const
            {
                ttd_event result{.position = event.step, .ip = event.ip, .address = event.address, .size = event.size, .kind = event.kind};
                if (event.kind == access_kind::execute)
                {
                    if (this->native().has_instruction_bytes() && event.size < ttd::inline_data_limit)
                    {
                        const auto bytes = std::as_bytes(std::span(event.payload)).first(static_cast<size_t>(event.size));
                        result.data.assign(bytes.begin(), bytes.end());
                    }
                }
                else
                {
                    result.data = this->native().access_data(event);
                }
                return result;
            }

            std::vector<ttd_event> events(const std::vector<ttd::access_event>& events) const
            {
                std::vector<ttd_event> result{};
                result.reserve(events.size());
                for (const auto& event : events)
                {
                    result.push_back(this->event(event));
                }
                return result;
            }

            std::vector<ttd_history_entry> history(const uint64_t address, const uint64_t size, const uint64_t end) const
            {
                constexpr auto kinds = static_cast<uint64_t>(access_kind::read) | static_cast<uint64_t>(access_kind::write) |
                                       static_cast<uint64_t>(access_kind::host_write);
                std::vector<std::optional<uint8_t>> value(static_cast<size_t>(size));
                std::vector<ttd_history_entry> result{};
                for (const auto& access : this->native().accesses(address, size, 0, end, kinds))
                {
                    auto event = this->event(access);
                    for (size_t i = 0; i < event.data.size(); ++i)
                    {
                        const auto byte_address = event.address + i;
                        if (byte_address >= address && byte_address - address < size)
                        {
                            value[static_cast<size_t>(byte_address - address)] = static_cast<uint8_t>(event.data[i]);
                        }
                    }
                    result.push_back({.event = std::move(event), .value = value});
                }
                return result;
            }

          private:
            std::shared_ptr<ttd::trace> trace_;
        };

        struct ttd_difference
        {
            std::optional<uint64_t> first_number{};
            std::optional<ttd_event> first{};
            std::optional<uint64_t> second_number{};
            std::optional<ttd_event> second{};
        };

        std::optional<ttd_difference> first_difference(const ttd_trace& first, const ttd_trace& second)
        {
            const auto difference = ttd::first_difference(first.native(), second.native());
            if (!difference)
            {
                return std::nullopt;
            }
            ttd_difference result{};
            if (difference->first)
            {
                result.first_number = difference->first_number;
                result.first = first.event(*difference->first);
            }
            if (difference->second)
            {
                result.second_number = difference->second_number;
                result.second = second.event(*difference->second);
            }
            return result;
        }

        class ttd_event_iterator
        {
          public:
            ttd_event_iterator(const ttd_trace& recorded, const uint64_t first, const uint64_t kinds)
                : trace_(recorded),
                  reader_(recorded.native(), first),
                  kinds_(kinds)
            {
            }

            ttd_event next()
            {
                const auto event = this->reader_.next(this->kinds_);
                if (!event)
                {
                    throw nb::stop_iteration();
                }
                return this->trace_.event(*event);
            }

          private:
            ttd_trace trace_;
            ttd::event_reader reader_;
            uint64_t kinds_{};
        };

        class ttd_replay
        {
          public:
            ttd_replay(ttd_trace recorded, sogen_windows_emulator& emulator)
                : trace_(std::move(recorded)),
                  emulator_(&emulator)
            {
                ttd::require_deterministic(emulator.native());
            }

            ttd::seek_result seek(const uint64_t position) const
            {
                return ttd::seek(this->emulator_->native(), this->trace_.native(), position);
            }

            std::vector<ttd::recovered_string> strings(const size_t minimum_length) const
            {
                auto& emulator = this->emulator_->native();
                std::optional<ttd::string_scanner> scanner{};
                ttd::replay_to_end(emulator, this->trace_.native(), [&] {
                    scanner.emplace(emulator, minimum_length);
                    scanner->scan_initial_memory();
                });
                scanner->finish();
                return scanner->results();
            }

            std::vector<ttd::recovered_buffer> buffers() const
            {
                auto& emulator = this->emulator_->native();
                std::optional<ttd::buffer_scanner> scanner{};
                ttd::replay_to_end(emulator, this->trace_.native(), [&] { scanner.emplace(emulator, this->trace_.native()); });
                scanner->finish();
                return scanner->results();
            }

            std::vector<ttd::self_modifying_hit> self_modifying_waves() const
            {
                auto& emulator = this->emulator_->native();
                std::optional<ttd::replay_selfmod_scanner> scanner{};
                ttd::replay_to_end(emulator, this->trace_.native(), [&] { scanner.emplace(emulator, this->trace_.native()); });
                scanner->finish();
                return scanner->hits();
            }

            std::vector<std::string> manifest_differences() const
            {
                return ttd::manifest_differences(this->emulator_->native(), this->trace_.native());
            }

            uint64_t position() const
            {
                return this->emulator_->native().get_executed_instructions();
            }

            sogen_windows_emulator& emulator() const
            {
                return *this->emulator_;
            }

          private:
            ttd_trace trace_;
            sogen_windows_emulator* emulator_{};
        };

        uint64_t end_position(const std::optional<uint64_t>& end)
        {
            return end.value_or(UINT64_MAX);
        }

        sogen_windows_emulator create_ttd_emulator(const nb::object& application, const nb::object& args, const nb::kwargs& kwargs)
        {
            for (const auto* forced : {"backend", "use_relative_time"})
            {
                if (kwargs.contains(forced))
                {
                    throw nb::value_error("TTD emulators always use the Unicorn backend and the relative clock");
                }
            }
            nb::dict settings{};
            for (const auto& [key, value] : kwargs)
            {
                settings[key] = value;
            }
            if (kwargs.contains("headless") && !nb::cast<bool>(kwargs["headless"]))
            {
                throw nb::value_error("TTD emulators are always headless: live window input cannot be replayed");
            }
            settings["backend"] = backend_type::unicorn;
            settings["use_relative_time"] = true;
            settings["headless"] = true;
            sogen_windows_emulator emulator(create_application_emulator(application, args, nb::borrow<nb::kwargs>(settings)));
            ttd::install_cpuid_overrides(emulator.native());
            return emulator;
        }

        void register_types(nb::module_& m)
        {
            nb::enum_<access_kind>(m, "Access", nb::is_flag(), "Kinds of recorded events; combine with |")
                .value("READ", access_kind::read)
                .value("WRITE", access_kind::write, "A write by a guest instruction")
                .value("EXECUTE", access_kind::execute)
                .value("HOST_WRITE", access_kind::host_write, "A write Sogen makes itself: syscall output, loader, exception frames")
                .export_values();
            m.attr("ALL") = static_cast<access_kind>(ttd::all_access_kinds);
            const nb::exception<ttd::divergence_error> divergence_error(m, "DivergenceError", PyExc_RuntimeError);

            nb::class_<ttd_event>(m, "Event", "One recorded access. Position N is the state after instruction N.")
                .def_ro("position", &ttd_event::position, "1-based number of the instruction performing the access")
                .def_ro("ip", &ttd_event::ip)
                .def_ro("address", &ttd_event::address)
                .def_ro("size", &ttd_event::size)
                .def_ro("kind", &ttd_event::kind)
                .def_prop_ro(
                    "data", [](const ttd_event& self) { return to_bytes(self.data); },
                    "Bytes read or written; instruction bytes for executes")
                .def("__repr__", &ttd_event::repr);

            nb::class_<ttd_history_entry>(m, "HistoryEntry")
                .def_ro("event", &ttd_history_entry::event)
                .def_ro("value", &ttd_history_entry::value, "The range after the event; None for bytes not seen yet");

            nb::class_<ttd::self_modifying_hit>(m, "SelfModifyingHit", "An executed instruction whose bytes were written earlier")
                .def_ro("address", &ttd::self_modifying_hit::address)
                .def_ro("size", &ttd::self_modifying_hit::size)
                .def_ro("write_position", &ttd::self_modifying_hit::write_step)
                .def_ro("write_ip", &ttd::self_modifying_hit::write_ip)
                .def_ro("execute_position", &ttd::self_modifying_hit::execute_step)
                .def_ro("execute_ip", &ttd::self_modifying_hit::execute_ip)
                .def_ro("executions", &ttd::self_modifying_hit::executions);

            nb::class_<ttd::recovered_string>(m, "RecoveredString")
                .def_ro("address", &ttd::recovered_string::address)
                .def_ro("position", &ttd::recovered_string::step, "Position at which the string was last seen extended")
                .def_ro("encoding", &ttd::recovered_string::encoding, "ascii or utf16le")
                .def_ro("value", &ttd::recovered_string::value);

            nb::class_<ttd::recovered_buffer>(m, "RecoveredBuffer")
                .def_ro("address", &ttd::recovered_buffer::address)
                .def_ro("size", &ttd::recovered_buffer::size)
                .def_ro("first_position", &ttd::recovered_buffer::first_step)
                .def_ro("last_position", &ttd::recovered_buffer::last_step)
                .def_ro("writer_ip", &ttd::recovered_buffer::writer_ip)
                .def_ro("writes", &ttd::recovered_buffer::writes)
                .def_ro("kind", &ttd::recovered_buffer::kind)
                .def_ro("preview", &ttd::recovered_buffer::preview)
                .def_prop_ro("data", [](const ttd::recovered_buffer& self) {
                    return nb::bytes(reinterpret_cast<const char*>(self.data.data()), self.data.size());
                });

            nb::class_<ttd::seek_result>(m, "SeekResult")
                .def_ro("checkpoint", &ttd::seek_result::checkpoint, "Position of the checkpoint the seek restored")
                .def_ro("verified_events", &ttd::seek_result::verified_events);
        }

        void register_trace(nb::module_& m)
        {
            nb::class_<ttd_event_iterator>(m, "EventIterator")
                .def("__iter__", [](nb::handle self) { return self; })
                .def("__next__", &ttd_event_iterator::next);

            nb::class_<ttd_trace>(m, "Trace", "A recorded trace, queried without replaying")
                .def(nb::init<std::filesystem::path>(), nb::arg("path"))
                .def("close", &ttd_trace::close, "Release the trace file; replays and iterators keep their own reference")
                .def("__enter__", [](nb::handle self) { return self; })
                .def(
                    "__exit__", [](ttd_trace& self, const nb::args&) { self.close(); }, nb::arg("args"))
                .def_prop_ro("instruction_count", [](const ttd_trace& self) { return self.native().metadata().instruction_count; })
                .def_prop_ro("event_count", [](const ttd_trace& self) { return self.native().metadata().event_count; })
                .def_prop_ro("access_mask", [](const ttd_trace& self) { return static_cast<access_kind>(self.native().access_mask()); })
                .def_prop_ro(
                    "start_position", [](const ttd_trace& self) { return self.native().start_position(); },
                    "Position of the initial state: 0, or the fork position of a trace recorded after a seek")
                .def_prop_ro(
                    "manifest",
                    [](const ttd_trace& self) {
                        nb::dict manifest{};
                        for (const auto& [key, value] : self.native().manifest())
                        {
                            manifest[nb::str(key.data(), key.size())] = nb::str(value.data(), value.size());
                        }
                        return manifest;
                    },
                    "How the trace was recorded (build, backend, cpuid, emulation_root, registry, system_dlls, windows_version, "
                    "executable, command_line, checkpoint_interval, tool, and the entries passed to record); empty for older "
                    "traces")
                .def_prop_ro(
                    "checkpoints",
                    [](const ttd_trace& self) {
                        std::vector<uint64_t> positions{self.native().start_position()};
                        for (const auto& checkpoint : self.native().checkpoints())
                        {
                            positions.push_back(checkpoint.step);
                        }
                        return positions;
                    },
                    "Positions a seek can restore directly, starting with start_position")
                .def(
                    "accesses",
                    [](const ttd_trace& self, const uint64_t address, const uint64_t size, const access_kind kinds, const uint64_t start,
                       const std::optional<uint64_t> end) {
                        return self.events(self.native().accesses(address, size, start, end_position(end), static_cast<uint64_t>(kinds)));
                    },
                    nb::arg("address"), nb::arg("size") = 1, nb::arg("kinds") = static_cast<access_kind>(ttd::all_access_kinds),
                    nb::arg("start") = 0, nb::arg("end") = nb::none(),
                    "Events overlapping [address, address + size) at positions start through end, in order")
                .def(
                    "next_access",
                    [](const ttd_trace& self, const uint64_t address, const uint64_t size, const uint64_t position,
                       const access_kind kinds) -> std::optional<ttd_event> {
                        const auto event = self.native().next_access(address, size, position, static_cast<uint64_t>(kinds));
                        return event ? std::optional(self.event(*event)) : std::nullopt;
                    },
                    nb::arg("address"), nb::arg("size") = 1, nb::arg("position") = 0,
                    nb::arg("kinds") = static_cast<access_kind>(ttd::all_access_kinds), "The first matching event after position")
                .def(
                    "previous_access",
                    [](const ttd_trace& self, const uint64_t address, const uint64_t size, const uint64_t position,
                       const access_kind kinds) -> std::optional<ttd_event> {
                        const auto event = self.native().previous_access(address, size, position, static_cast<uint64_t>(kinds));
                        return event ? std::optional(self.event(*event)) : std::nullopt;
                    },
                    nb::arg("address"), nb::arg("size") = 1, nb::arg("position"),
                    nb::arg("kinds") = static_cast<access_kind>(ttd::all_access_kinds), "The last matching event before position")
                .def("history", &ttd_trace::history, nb::arg("address"), nb::arg("size") = 8, nb::arg("end") = UINT64_MAX,
                     "Every read and write of the range up to end, with the range's value after each")
                .def(
                    "events",
                    [](const ttd_trace& self, const uint64_t first, const access_kind kinds) {
                        return ttd_event_iterator(self, first, static_cast<uint64_t>(kinds));
                    },
                    nb::arg("first") = 0, nb::arg("kinds") = static_cast<access_kind>(ttd::all_access_kinds),
                    "Iterate events from event number first")
                .def(
                    "event", [](const ttd_trace& self, const uint64_t number) { return self.event(self.native().event_at(number)); },
                    nb::arg("number"))
                .def(
                    "self_modifying_code", [](const ttd_trace& self) { return self.native().self_modifying_code(); },
                    "Executed instructions whose bytes a guest instruction wrote earlier");

            nb::class_<ttd_difference>(m, "Difference", "The first event two traces record differently")
                .def_ro("first", &ttd_difference::first, "The first trace's event; None when it has no further event")
                .def_ro("first_number", &ttd_difference::first_number)
                .def_ro("second", &ttd_difference::second, "The second trace's event; None when it has no further event")
                .def_ro("second_number", &ttd_difference::second_number);

            m.def("first_difference", &first_difference, nb::arg("first"), nb::arg("second"), nb::call_guard<nb::gil_scoped_release>(),
                  "The first event the traces record differently (kinds both recorded, with their data), from the later "
                  "start_position to the earlier end; None when they agree. For a recorded fork and its parent this is where "
                  "the change first shows.");
        }

        void register_replay(nb::module_& m)
        {
            m.def(
                "create_emulator",
                [](const nb::object& application, const nb::object& args, const nb::kwargs& kwargs) {
                    return create_ttd_emulator(application, args, kwargs);
                },
                nb::arg("application"), nb::arg("args") = nb::none(), nb::arg("kwargs"),
                "A Windows emulator set up for recording and replay: Unicorn, the relative clock, headless (no live window "
                "input, which a replay cannot repeat), and the CPUID results traces depend on. Accepts the keyword arguments of "
                "sogen.windows.create_application except backend and use_relative_time.");

            m.def(
                "record",
                [](sogen_windows_emulator& emulator, const std::filesystem::path& path, const uint64_t checkpoint_interval,
                   const uint64_t max_instructions, const access_kind kinds, const std::optional<nb::dict>& manifest) {
                    ttd::manifest_entries entries{{"tool", "sogen.ttd"}};
                    if (manifest)
                    {
                        for (const auto& [key, value] : *manifest)
                        {
                            entries.emplace_back(nb::cast<std::string>(key), nb::cast<std::string>(value));
                        }
                    }
                    {
                        const nb::gil_scoped_release release{};
                        ttd::record(emulator.native(), {.path = path,
                                                        .access_mask = static_cast<uint64_t>(kinds),
                                                        .checkpoint_interval = checkpoint_interval,
                                                        .max_instructions = max_instructions,
                                                        .manifest = std::move(entries)});
                    }
                    return ttd_trace(path);
                },
                nb::arg("emulator"), nb::arg("path"), nb::arg("checkpoint_interval") = 500000, nb::arg("max_instructions") = 0,
                nb::arg("kinds") = static_cast<access_kind>(ttd::all_access_kinds), nb::arg("manifest") = nb::none(),
                "Run the emulator from its current state until the process exits or max_instructions more instructions ran, "
                "recording a trace. A checkpoint_interval of 0 keeps only the initial state. manifest: extra str entries for "
                "Trace.manifest. Recording after Replay.seek forks the replayed trace: the new trace starts at that position.");

            nb::class_<ttd_replay>(m, "Replay",
                                   "Moves an emulator to recorded positions. After a seek the emulator is a normal emulator at that "
                                   "position: change registers or memory and start() it to fork the recording.")
                .def(nb::init<ttd_trace, sogen_windows_emulator&>(), nb::arg("trace"), nb::arg("emulator"), nb::keep_alive<1, 3>())
                .def("seek", &ttd_replay::seek, nb::arg("position"), nb::call_guard<nb::gil_scoped_release>(),
                     "Restore the last checkpoint at or before position and replay to it, verifying every recorded event. Raises "
                     "DivergenceError where the replay diverges from the recording, and RuntimeError for a trace recorded with "
                     "another backend or other CPUID results.")
                .def("strings", &ttd_replay::strings, nb::arg("minimum_length") = 6, nb::call_guard<nb::gil_scoped_release>(),
                     "Replay the whole trace (verified) and return the ASCII and UTF-16LE strings that appeared in memory, "
                     "including transient ones, ordered by address. Leaves the emulator at the end of the trace.")
                .def("buffers", &ttd_replay::buffers, nb::call_guard<nb::gil_scoped_release>(),
                     "Replay the whole trace (verified; needs write events) and return the buffers guest code wrote. Leaves "
                     "the emulator at the end of the trace.")
                .def("self_modifying_waves", &ttd_replay::self_modifying_waves, nb::call_guard<nb::gil_scoped_release>(),
                     "Replay the whole trace (verified; needs write events) and return the first written-then-executed "
                     "instruction of each wave (at most 256). Trace.self_modifying_code lists every hit without replaying.")
                .def("manifest_differences", &ttd_replay::manifest_differences,
                     "After a seek: the recorded inputs outside the checkpoints (emulation_root, registry, system_dlls, "
                     "build) that differ for this emulator. A divergence error lists them too.")
                .def_prop_ro("position", &ttd_replay::position)
                .def_prop_ro("emulator", &ttd_replay::emulator, nb::rv_policy::reference_internal);
        }
    }

    void register_ttd_bindings(nb::module_& m)
    {
        register_types(m);
        register_trace(m);
        register_replay(m);
    }
}
