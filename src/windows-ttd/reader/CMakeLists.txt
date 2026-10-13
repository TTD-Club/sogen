# The trace reader: reads TTD traces without an emulator (no windows-emulator, no CPU backend, no disassembler).
file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
  *.cpp
  *.hpp
)

list(SORT SRC_FILES)

add_library(windows-ttd-reader STATIC ${SRC_FILES})

sogen_assign_source_group(${SRC_FILES})

target_link_libraries(windows-ttd-reader PUBLIC
  emulator-common
)

target_include_directories(windows-ttd-reader INTERFACE "${CMAKE_CURRENT_LIST_DIR}")

sogen_strip_target(windows-ttd-reader)
