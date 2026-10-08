#include <nanobind/nanobind.h>

#include "sogen_internal.hpp"

#include <ttd_buffer_scan.hpp>
#include <ttd_session.hpp>
#include <ttd_string_scan.hpp>
#include <ttd_trace.hpp>
#include <ttd_ui.hpp>

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

        struct ttd_syscall
        {
            uint64_t position{};
            uint32_t id{};
            std::optional<std::string> name{};
            uint64_t result{};
            uint64_t event_number{};
            uint64_t event_count{};

            std::string repr() const
            {
                std::ostringstream text;
                text << std::hex << "Syscall(position=0x" << this->position << ", name=" << this->name.value_or("<unknown>")
                     << ", result=0x" << this->result << ", event_count=" << std::dec << this->event_count << ")";
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
            ttd_event_iterator(const ttd_trace& recorded, const uint64_t first, const uint64_t kinds, const std::optional<uint32_t> thread)
                : trace_(recorded),
                  reader_(recorded.native(), first),
                  kinds_(kinds),
                  thread_(thread)
            {
                if (thread && recorded.native().threads().switches.empty())
                {
                    throw std::runtime_error("This TTD trace does not record threads");
                }
            }

            ttd_event next()
            {
                while (true)
                {
                    const auto event = this->reader_.next(this->kinds_);
                    if (!event)
                    {
                        throw nb::stop_iteration();
                    }
                    if (!this->thread_ || this->thread_of(this->reader_.last_number()) == *this->thread_)
                    {
                        return this->trace_.event(*event);
                    }
                }
            }

          private:
            ttd_trace trace_;
            ttd::event_reader reader_;
            uint64_t kinds_{};
            std::optional<uint32_t> thread_{};
            // The switch in effect for the last event; events are read in order.
            size_t switch_{};

            std::optional<uint32_t> thread_of(const uint64_t number)
            {
                const auto& switches = this->trace_.native().threads().switches;
                while (this->switch_ + 1 < switches.size() && switches[this->switch_ + 1].event_number <= number)
                {
                    ++this->switch_;
                }
                if (switches[this->switch_].event_number > number)
                {
                    return std::nullopt;
                }
                return switches[this->switch_].thread_id;
            }
        };

        class ttd_replay
        {
          public:
            ttd_replay(ttd_trace recorded, sogen_windows_emulator& emulator, const bool strict)
                : trace_(std::move(recorded)),
                  emulator_(&emulator),
                  strict_(strict)
            {
                ttd::require_deterministic(emulator.native());
            }

            ttd::seek_result seek(const uint64_t position) const
            {
                this->replayed_.reset();
                const auto result = ttd::seek(this->emulator_->native(), this->trace_.native(), position, this->strict_);
                this->replayed_ = position;
                return result;
            }

            ttd::seek_result run_to(const uint64_t position) const
            {
                if (this->replayed_ != this->emulator_->native().get_executed_instructions())
                {
                    throw std::runtime_error("Replay.run_to continues where the last seek or run_to stopped, but the emulator ran "
                                             "since; seek instead");
                }
                this->replayed_.reset();
                const auto result = ttd::run_to(this->emulator_->native(), this->trace_.native(), position, this->strict_);
                this->replayed_ = position;
                return result;
            }

            std::vector<ttd::recovered_string> strings(const size_t minimum_length) const
            {
                auto& emulator = this->emulator_->native();
                std::optional<ttd::string_scanner> scanner{};
                ttd::replay_to_end(
                    emulator, this->trace_.native(),
                    [&] {
                        scanner.emplace(emulator, minimum_length);
                        scanner->scan_initial_memory();
                    },
                    this->strict_);
                scanner->finish();
                return scanner->results();
            }

            std::vector<ttd::recovered_buffer> buffers() const
            {
                auto& emulator = this->emulator_->native();
                std::optional<ttd::buffer_scanner> scanner{};
                ttd::replay_to_end(
                    emulator, this->trace_.native(), [&] { scanner.emplace(emulator, this->trace_.native()); }, this->strict_);
                scanner->finish();
                return scanner->results();
            }

            std::vector<ttd::self_modifying_hit> self_modifying_waves() const
            {
                auto& emulator = this->emulator_->native();
                std::optional<ttd::replay_selfmod_scanner> scanner{};
                ttd::replay_to_end(
                    emulator, this->trace_.native(), [&] { scanner.emplace(emulator, this->trace_.native()); }, this->strict_);
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
            bool strict_{};
            // The position the last successful seek or run_to reached; run_to checks the emulator is still there.
            mutable std::optional<uint64_t> replayed_{};
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
            settings["backend"] = backend_type::unicorn;
            settings["use_relative_time"] = true;
            sogen_windows_emulator emulator(
                create_application_emulator(application, args, nb::borrow<nb::kwargs>(settings), [](std::unique_ptr<ui_backend> inner) {
                    return std::unique_ptr<ui_backend>(std::make_unique<ttd::recordable_ui_backend>(std::move(inner)));
                }));
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

            nb::class_<ttd::ui_input_entry>(m, "UiInput", "A host window event delivered while recording")
                .def_ro("position", &ttd::ui_input_entry::step)
                .def_ro("event_number", &ttd::ui_input_entry::event_number, "Number of events recorded before it")
                .def_ro("checkpoint", &ttd::ui_input_entry::checkpoint, "Index of the last checkpoint before it")
                .def_ro("window", &ttd::ui_input_entry::window)
                .def_ro("message", &ttd::ui_input_entry::message)
                .def_ro("wparam", &ttd::ui_input_entry::wparam)
                .def_ro("lparam", &ttd::ui_input_entry::lparam);

            nb::class_<ttd_syscall>(m, "Syscall", "A syscall the recording dispatched")
                .def_ro("position", &ttd_syscall::position, "Position of the syscall instruction")
                .def_ro("id", &ttd_syscall::id)
                .def_ro("name", &ttd_syscall::name, "As the recording emulator's ntdll or win32u exports it")
                .def_ro("result", &ttd_syscall::result, "RAX after the handler ran (the NTSTATUS for most syscalls)")
                .def_ro("event_number", &ttd_syscall::event_number, "Number of events recorded before its handler ran")
                .def_ro("event_count", &ttd_syscall::event_count,
                        "Number of events its handler produced (host writes, and descriptor table reads when it loads segment "
                        "registers): events event_number to event_number + event_count - 1")
                .def("__repr__", &ttd_syscall::repr);

            nb::class_<ttd::module_entry>(m, "Module", "A module mapped while recording")
                .def_ro("name", &ttd::module_entry::name)
                .def_ro("path", &ttd::module_entry::path, "Guest path")
                .def_ro("base", &ttd::module_entry::base)
                .def_ro("size", &ttd::module_entry::size)
                .def_ro("load_position", &ttd::module_entry::load_step, "The trace's start for modules mapped before it")
                .def_ro("load_event_number", &ttd::module_entry::load_event_number, "Number of events recorded before the load")
                .def_ro("unload_position", &ttd::module_entry::unload_step, "None while still mapped at the end")
                .def_ro("unload_event_number", &ttd::module_entry::unload_event_number)
                .def("__repr__", [](const ttd::module_entry& self) {
                    std::ostringstream text;
                    text << std::hex << "Module(name=" << self.name << ", base=0x" << self.base << ", size=0x" << self.size
                         << ", load_position=0x" << self.load_step << ")";
                    return text.str();
                });

            nb::class_<ttd::thread_switch>(m, "ThreadSwitch", "Thread thread_id runs from event event_number on")
                .def_ro("position", &ttd::thread_switch::step, "Position of the thread's first instruction after the switch")
                .def_ro("event_number", &ttd::thread_switch::event_number)
                .def_ro("thread_id", &ttd::thread_switch::thread_id)
                .def("__repr__", [](const ttd::thread_switch& self) {
                    std::ostringstream text;
                    text << "ThreadSwitch(position=0x" << std::hex << self.step << ", event_number=" << std::dec << self.event_number
                         << ", thread_id=" << self.thread_id << ")";
                    return text.str();
                });

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
                .def_ro("verified_events", &ttd::seek_result::verified_events)
                .def_ro("substituted_inputs", &ttd::seek_result::substituted_inputs,
                        "Syscalls whose live writes or result differed (a network answer, a missing file), and host writes "
                        "outside syscalls whose live bytes differed, that took the recorded ones");
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
                    "ui_inputs",
                    [](const ttd_trace& self) {
                        const auto inputs = self.native().ui_inputs();
                        return std::vector<ttd::ui_input_entry>(inputs.begin(), inputs.end());
                    },
                    "Host window events delivered while recording, which a replay delivers again")
                .def_prop_ro(
                    "syscalls",
                    [](const ttd_trace& self) {
                        const auto& native = self.native();
                        std::vector<ttd_syscall> syscalls{};
                        syscalls.reserve(native.syscalls().size());
                        for (const auto& entry : native.syscalls())
                        {
                            const auto name = native.syscall_name(entry.id);
                            syscalls.push_back({.position = entry.step,
                                                .id = entry.id,
                                                .name = name ? std::optional<std::string>(*name) : std::nullopt,
                                                .result = entry.result,
                                                .event_number = entry.event_number,
                                                .event_count = entry.event_count});
                        }
                        return syscalls;
                    },
                    "Every syscall the recording dispatched, in order; empty for traces recorded before syscalls were recorded")
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
                    [](const ttd_trace& self, const uint64_t first, const access_kind kinds, const std::optional<uint32_t> thread) {
                        return ttd_event_iterator(self, first, static_cast<uint64_t>(kinds), thread);
                    },
                    nb::arg("first") = 0, nb::arg("kinds") = static_cast<access_kind>(ttd::all_access_kinds),
                    nb::arg("thread") = nb::none(), "Iterate events from event number first, optionally only those of one thread")
                .def_prop_ro(
                    "modules",
                    [](const ttd_trace& self) {
                        const auto modules = self.native().modules();
                        return std::vector<ttd::module_entry>(modules.begin(), modules.end());
                    },
                    "Every module mapped while recording, in load order (those mapped before the start first); empty for "
                    "traces recorded before modules were recorded")
                .def(
                    "module_at",
                    [](const ttd_trace& self, const uint64_t address, const uint64_t position) -> std::optional<ttd::module_entry> {
                        const auto* mod = self.native().module_at(address, position);
                        return mod ? std::optional(*mod) : std::nullopt;
                    },
                    nb::arg("address"), nb::arg("position"), "The module whose image holds address at position, or None")
                .def_prop_ro(
                    "thread_switches", [](const ttd_trace& self) { return self.native().threads().switches; },
                    "Where another thread starts running, in order (the first entry is the thread running at the start); "
                    "empty for traces recorded before threads were recorded")
                .def_prop_ro(
                    "thread_names", [](const ttd_trace& self) { return self.native().threads().names; },
                    "Name of each thread that ran, by id; empty for unnamed threads")
                .def(
                    "thread_at", [](const ttd_trace& self, const uint64_t position) { return self.native().thread_at(position); },
                    nb::arg("position"), "Id of the thread executing the instruction at position, or None before the first switch")
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
                "A Windows emulator set up for recording and replay: Unicorn, the relative clock, the CPUID results traces "
                "depend on, and a UI whose window input a recording logs and a replay delivers again (headless=True for no "
                "window). Accepts the keyword arguments of sogen.windows.create_application except backend and "
                "use_relative_time.");

            m.def(
                "inject_ui_event",
                [](sogen_windows_emulator& emulator, const uint64_t window, const uint32_t message, const uint64_t wparam,
                   const uint64_t lparam) {
                    auto* ui = dynamic_cast<ttd::recordable_ui_backend*>(&emulator.native().ui());
                    if (!ui)
                    {
                        throw nb::value_error("inject_ui_event needs an emulator from ttd.create_emulator");
                    }
                    ui->inject({.window = window, .message = message, .wParam = wparam, .lParam = lparam});
                },
                nb::arg("emulator"), nb::arg("window"), nb::arg("message"), nb::arg("wparam") = 0, nb::arg("lparam") = 0,
                "Deliver a window event at the emulator's next UI pump as if the host window produced it; a recording logs "
                "it like live input");

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
                                   "position: change registers or memory and start() it to fork the recording. Host writes "
                                   "(syscall results, network data) are the environment's input: one whose live bytes differ "
                                   "from the recording takes the recorded bytes, unless strict=True, which reports it as a "
                                   "divergence (and exposes emulator bugs such as uninitialized host bytes).")
                .def(nb::init<ttd_trace, sogen_windows_emulator&, bool>(), nb::arg("trace"), nb::arg("emulator"), nb::arg("strict") = false,
                     nb::keep_alive<1, 3>())
                .def("seek", &ttd_replay::seek, nb::arg("position"), nb::call_guard<nb::gil_scoped_release>(),
                     "Restore the last checkpoint at or before position and replay to it, verifying every recorded event. Raises "
                     "DivergenceError where the replay diverges from the recording, and RuntimeError for a trace recorded with "
                     "another backend or other CPUID results.")
                .def("run_to", &ttd_replay::run_to, nb::arg("position"), nb::call_guard<nb::gil_scoped_release>(),
                     "Replay forward from where the last seek or run_to stopped to position, verifying every recorded event, "
                     "without restoring a checkpoint: much faster than seek for short moves forward. Raises RuntimeError when "
                     "the emulator ran since, and IndexError for a position before the current one. Changes made to the "
                     "emulator in between that the replay does not observe before position go unnoticed; seek after "
                     "changing it.")
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
