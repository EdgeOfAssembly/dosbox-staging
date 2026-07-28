# Linux+X11 product: debugger_win32.cpp is intentionally not listed
# (WIN32_Console / AllocConsole — host Windows only).

set(DEBUGGER_SRC
  debugger.cpp
  debugger_disasm.cpp
  debugger_gui.cpp)

target_sources(libdosboxcommon PRIVATE
  debugger.cpp
  debugger_disasm.cpp
  debugger_gui.cpp)

target_link_libraries(libdosboxcommon PRIVATE libpdcurses)
