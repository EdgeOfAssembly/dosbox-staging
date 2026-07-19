libcontrol_sources = files('control_socket.cpp')

libcontrol = static_library(
    'control',
    libcontrol_sources,
    include_directories: incdir,
    dependencies: [
        libloguru_dep,
        threads_dep,
    ],
    cpp_args: warnings,
)

libcontrol_dep = declare_dependency(link_with: libcontrol)

internal_deps += libcontrol_dep
