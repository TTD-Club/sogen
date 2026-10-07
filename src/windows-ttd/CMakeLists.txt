file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
  *.cpp
  *.hpp
)

list(SORT SRC_FILES)

add_library(windows-ttd STATIC ${SRC_FILES})

sogen_assign_source_group(${SRC_FILES})

target_link_libraries(windows-ttd PUBLIC
  windows-emulator
)

target_include_directories(windows-ttd INTERFACE "${CMAKE_CURRENT_LIST_DIR}")

sogen_strip_target(windows-ttd)
