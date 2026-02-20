libdebug_trace_sources = files(
    'game_trace.cpp',
    'instruction_logger.cpp',
    'interrupt_logger.cpp',
    'file_io_logger.cpp',
    'video_mode_logger.cpp',
    'exec_logger.cpp',
)

libdebug_trace = static_library(
    'debug_trace',
    libdebug_trace_sources,
    include_directories: incdir,
    dependencies: [
        libloguru_dep,
    ],
    cpp_args: warnings,
)

libdebug_trace_dep = declare_dependency(link_with: libdebug_trace)

internal_deps += libdebug_trace_dep
