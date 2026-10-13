# A trace inspector that links only the reader: what a consumer without the emulator can do.
add_executable(ttd-inspect ttd_inspect.cpp)

target_link_libraries(ttd-inspect PRIVATE
  windows-ttd-reader
)
