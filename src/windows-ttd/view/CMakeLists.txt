# Registers at a trace position (cpu_view): the reader plus a standalone Unicorn CPU, without windows-emulator.
file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
  *.cpp
  *.hpp
)

list(SORT SRC_FILES)

add_library(windows-ttd-view STATIC ${SRC_FILES})

sogen_assign_source_group(${SRC_FILES})

target_link_libraries(windows-ttd-view PUBLIC
  windows-ttd-reader
  emulator
)

target_link_libraries(windows-ttd-view PRIVATE
  unicorn-emulator
)

target_include_directories(windows-ttd-view INTERFACE "${CMAKE_CURRENT_LIST_DIR}")

sogen_strip_target(windows-ttd-view)
