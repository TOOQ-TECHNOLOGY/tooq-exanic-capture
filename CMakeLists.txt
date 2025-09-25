cmake_minimum_required(VERSION 3.15)

project(main_c_exe C)

# Equivalente a -std=gnu99
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Equivalente a -O3 -Wall
add_compile_options(-O3 -Wall)

# Executável
add_executable(exanic-capture src/main.c)

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