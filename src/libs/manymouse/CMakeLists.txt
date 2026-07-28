
if(C_MANYMOUSE)

  # Linux+X11 only: evdev + XInput2 (no macOS/Windows backends)
  add_library(libmanymouse STATIC
    linux_evdev.c
    manymouse.c
    x11_xinput2.c
  )

  target_link_libraries(dosbox PRIVATE
    $<IF:$<BOOL:${SUPPORT_XINPUT2}>,${X11_Xinput_LIB},>
  )

endif()
