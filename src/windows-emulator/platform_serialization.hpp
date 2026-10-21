#pragma once

#include "std_include.hpp"

#include <serialization.hpp>
#include <platform/window.hpp>

// Platform structures with padding, written with the padding zeroed (see buffer_serializer::write_zero_padded). Each
// is written as the same bytes as before apart from the padding, and read back as before.
namespace sogen
{
    inline void serialize(utils::buffer_serializer& buffer, const msg& value)
    {
        buffer.write_zero_padded(value, &msg::window, &msg::message, &msg::wParam, &msg::lParam, &msg::time, &msg::pt);
    }

    inline void serialize(utils::buffer_serializer& buffer, const qmsg& value)
    {
        buffer.write_zero_padded(value, &qmsg::message, &qmsg::wParam, &qmsg::lParam);
    }

    // A union of a status and a pointer: the pointer covers both.
    template <typename Traits>
    void serialize(utils::buffer_serializer& buffer, const IO_STATUS_BLOCK<Traits>& value)
    {
        buffer.write_zero_padded(value, &IO_STATUS_BLOCK<Traits>::Pointer, &IO_STATUS_BLOCK<Traits>::Information);
    }

    template <typename Traits>
    void serialize(utils::buffer_serializer& buffer, const EMU_WSABUF<Traits>& value)
    {
        buffer.write_zero_padded(value, &EMU_WSABUF<Traits>::len, &EMU_WSABUF<Traits>::buf);
    }
}
