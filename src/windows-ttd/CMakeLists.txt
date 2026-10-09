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

target_link_libraries(windows-ttd PRIVATE
  backend-selection
  disassembler
)

target_include_directories(windows-ttd INTERFACE "${CMAKE_CURRENT_LIST_DIR}")

set(TTD_BUILD_INFO "${CMAKE_CURRENT_BINARY_DIR}/generated/ttd_build_info.hpp")
add_custom_target(windows-ttd-build-info
  COMMAND "${CMAKE_COMMAND}" "-DSOURCE_DIR=${CMAKE_CURRENT_LIST_DIR}" "-DOUTPUT=${TTD_BUILD_INFO}"
    -P "${CMAKE_CURRENT_LIST_DIR}/ttd_build_info.cmake"
  BYPRODUCTS "${TTD_BUILD_INFO}"
  COMMENT "Recording the Sogen commit for TTD manifests"
)
add_dependencies(windows-ttd windows-ttd-build-info)
target_include_directories(windows-ttd PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")

sogen_strip_target(windows-ttd)
