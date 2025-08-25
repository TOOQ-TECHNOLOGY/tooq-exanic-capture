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

# Includes e libs (equivalente a -I../libs e -L../libs/exanic -lexanic -lrt)
target_include_directories(exanic-capture PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../libs
)

# Diretório da lib exanic
target_link_directories(exanic-capture PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../libs/exanic
)

# Vincular exanic e rt
target_link_libraries(exanic-capture PRIVATE exanic rt)

# Instalação (equivalente a PREFIX=/usr/local e bin dir)
# Usa CMAKE_INSTALL_PREFIX (padrão: /usr/local). O DESTDIR pode ser usado no `cmake --install`.
install(TARGETS exanic-capture RUNTIME DESTINATION bin)
