cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

file(GLOB_RECURSE SOURCES "src/*.c")
file(GLOB_RECURSE HEADERS "include/*.h")

add_library(mog STATIC ${HEADERS} ${SOURCES})
target_include_directories(mog PUBLIC include)
set_target_properties(mog PROPERTIES PUBLIC_HEADER ${HEADERS})

install(TARGETS mog
  RUNTIME DESTINATION "bin"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
