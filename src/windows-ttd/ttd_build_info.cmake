# Writes OUTPUT with the commit Sogen is built from, leaving the file untouched when it is current so that only a new
# commit recompiles its users. Runs at build time: cmake -DSOURCE_DIR=... -DOUTPUT=... -P ttd_build_info.cmake

set(BUILD_COMMIT "unknown")
find_package(Git QUIET)
if(GIT_FOUND)
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${SOURCE_DIR}" describe --always --dirty --abbrev=12
    OUTPUT_VARIABLE DESCRIBED
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE RESULT
    ERROR_QUIET)
  if(RESULT EQUAL 0 AND DESCRIBED)
    set(BUILD_COMMIT "${DESCRIBED}")
  endif()
endif()

set(CONTENT "#pragma once\n\nnamespace sogen::ttd\n{\n    constexpr const char* build_commit = \"${BUILD_COMMIT}\";\n}\n")
set(CURRENT "")
if(EXISTS "${OUTPUT}")
  file(READ "${OUTPUT}" CURRENT)
endif()
if(NOT CURRENT STREQUAL CONTENT)
  file(WRITE "${OUTPUT}" "${CONTENT}")
endif()
