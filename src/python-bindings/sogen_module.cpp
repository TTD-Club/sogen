#include <nanobind/nanobind.h>

#include "sogen_internal.hpp"

namespace nb = nanobind;

namespace sogen::py
{
    namespace
    {
        void register_bindings(nb::module_& m)
        {
            m.doc() = "Sogen Python bindings";
            register_types_bindings(m);

            auto windows = m.def_submodule("windows", "Windows emulator bindings");
            register_windows_runtime_bindings(windows);
            auto linux_module = m.def_submodule("linux", "Linux emulator bindings");
            register_linux_runtime_bindings(linux_module);
            register_runtime_bindings(m);
            auto ttd = m.def_submodule("ttd", "Time travel debugging: record, query, and replay Windows emulation traces");
            register_ttd_bindings(ttd);
        }
    }
}

NB_MODULE(sogen, m)
{
#ifdef SOGEN_DISABLE_NANOBIND_LEAK_WARNINGS
    nb::set_leak_warnings(false);
#endif
    sogen::py::register_bindings(m);
}
