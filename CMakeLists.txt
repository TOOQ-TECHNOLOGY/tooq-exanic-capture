cmake_minimum_required(VERSION 3.15)

project(main_c_exe C)

# Equivalente a -std=gnu99
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Equivalente a -O3 -Wall
add_compile_options(-O3 -Wall)

# Executável
add_executable(exanic-capture src/main.c src/ptp_clock.c)

set(EXANIC_ROOT ${CMAKE_SOURCE_DIR}/libs)          # contém a pasta "exanic/"
set(EXANIC_DIR  ${EXANIC_ROOT}/exanic)             # onde está libexanic.a

# Para que "exanic/exanic.h" seja encontrado em libs/exanic/exanic.h
target_include_directories(exanic-capture PRIVATE ${EXANIC_ROOT})

# Opção A: declarar a lib estática como IMPORTED
add_library(exanic STATIC IMPORTED GLOBAL)
set_target_properties(exanic PROPERTIES
  IMPORTED_LOCATION "${EXANIC_DIR}/libexanic.a"
)

# Linka a lib exanic (e rt, se necessário)
target_link_libraries(exanic-capture PRIVATE exanic rt)

include(CTest)
if(BUILD_TESTING)
  add_executable(capture-test tests/capture_test.c src/ptp_clock.c)
  target_include_directories(capture-test PRIVATE ${EXANIC_ROOT})
  target_link_libraries(capture-test PRIVATE exanic rt)
  add_test(NAME capture-integrity COMMAND capture-test)
  add_executable(ptp-test tests/ptp_test.c src/ptp_clock.c)
  target_include_directories(ptp-test PRIVATE ${EXANIC_ROOT})
  target_link_libraries(ptp-test PRIVATE exanic rt)
  target_link_options(ptp-test PRIVATE "-Wl,--wrap=adjtimex")
  add_test(NAME ptp-continuity COMMAND ptp-test)
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME ptp-bridge COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_SOURCE_DIR}/tests/ptp_bridge_test.py)
  endif()
endif()
