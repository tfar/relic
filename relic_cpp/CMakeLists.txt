set(INCLUDE ${INCLUDE} ${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${INCLUDE})

# sources
list (APPEND CPP_SOURCES
  src/relic_bn.cpp
  src/relic_ec.cpp
  src/relic_hash.cpp
  src/relic_ibc.cpp
  )

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fPIC")

# build c++ binding
add_library(core OBJECT ${CPP_SOURCES})
if (STLIB)
  add_library(relic_cpp_s STATIC $<TARGET_OBJECTS:core>)
  target_link_libraries(relic_cpp_s ${RELIC_S})
  install(TARGETS relic_cpp_s ARCHIVE DESTINATION lib)
endif (STLIB)
if (SHLIB)
  add_library(relic_cpp SHARED $<TARGET_OBJECTS:core>)
  target_link_libraries(relic_cpp ${RELIC})
  install(TARGETS relic_cpp LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
endif (SHLIB)

# installation
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/" DESTINATION include/${RELIC})

# test code
macro(ADD_MODULE MODULE)
  add_executable(test_${MODULE} test/test_${MODULE}.cpp)
  if (STLIB)
    target_link_libraries(test_${MODULE} relic_cpp_s)
  else(STLIB)
    if (SHLIB)
      target_link_libraries(test_${MODULE} relic_cpp)
    endif(SHLIB)
  endif(STLIB)
  if (STBIN)
    set_target_properties(test_${MODULE} PROPERTIES LINK_SEARCH_END_STATIC 1)
  endif(STBIN)
  add_test(test_${MODULE} ${SIMUL} ${SIMAR} ${EXECUTABLE_OUTPUT_PATH}/test_${MODULE})
endmacro(ADD_MODULE)

ADD_MODULE(cpp_sh_ibs)
ADD_MODULE(cpp_vbnn_ibs)
ADD_MODULE(cpp_ibc)
ADD_MODULE(cpp_bn)

macro(ADD_BENCH_MODULE MODULE)
	add_executable(bench_${MODULE} bench/bench_${MODULE}.cpp)
if (STLIB)
  target_link_libraries(bench_${MODULE} relic_cpp_s)
else(STLIB)
  if (SHLIB)
    target_link_libraries(bench_${MODULE} relic_cpp)
  endif(SHLIB)
endif(STLIB)
	if (STBIN)
		set_target_properties(bench_${MODULE} PROPERTIES LINK_SEARCH_END_STATIC 1)
	endif(STBIN)
	add_test(bench_${MODULE} ${SIMUL} ${SIMAR} ${EXECUTABLE_OUTPUT_PATH}/bench_${MODULE})
endmacro(ADD_BENCH_MODULE)

ADD_BENCH_MODULE(cpp_ibc)
