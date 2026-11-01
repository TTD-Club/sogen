#pragma once

#include <string_view>

#include <utils/string.hpp>

namespace sogen
{
    // Every session but 0 keeps its private objects, such as the csrss API port and the win32k shared sections,
    // under \Sessions\<id>\. The guest runs in interactive session 1, so its system DLLs ask for those names.
    inline std::u16string_view strip_session_directory(const std::u16string_view name)
    {
        constexpr std::u16string_view session_directory = u"\\Sessions\\1";
        if (name.size() > session_directory.size() && name[session_directory.size()] == u'\\' &&
            utils::string::equals_ignore_case(name.substr(0, session_directory.size()), session_directory))
        {
            return name.substr(session_directory.size());
        }

        return name;
    }

} // namespace sogen
