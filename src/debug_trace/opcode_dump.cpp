// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Binary opcode dump subsystem.
//
// Produces a 1 MB flat memory image of the 8086 physical address space
// together with a 128 KB coverage bitmap.
//
// Flat image  (<filepath>):        1 byte per physical address (0x00000–0xFFFFF).
//   image[offset] == the byte at physical address `offset`.
//   Each executed instruction writes its raw bytes into the image at the exact
//   physical offsets — jumps, calls, and re-execution are naturally idempotent.
//
// Coverage bitmap (<filepath>.bitmap):  1 bit per physical address (128 KB).
//   Bit N is set iff physical address N was the start of an executed instruction.
//   The companion post-processor (scripts/tools/memory_dump_solution.py) uses
//   this bitmap as the exact set of disassembly entry points.
//
// Both files are memory-mapped (POSIX mmap / Win32 CreateFileMapping) for
// zero-copy, random-access writes.  This implementation currently requires
// memory-mapped files and does not provide a non-mmap fallback path.
//
// The output is independent of the human-readable text trace log — it can be
// enabled alone, together with the text log, or not at all.

#include "opcode_dump.h"

#include "hardware/memory.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
// Platform-specific includes
// ---------------------------------------------------------------------------

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// 8086 physical address space: 20-bit = 1 MB
static constexpr uint32_t PHYS_ADDR_SPACE = 0x100000u;
// Coverage bitmap: 1 bit per address → PHYS_ADDR_SPACE / 8 bytes
static constexpr uint32_t BITMAP_SIZE     = PHYS_ADDR_SPACE / 8u;

// ---------------------------------------------------------------------------
// File-local state
// ---------------------------------------------------------------------------

#ifdef _WIN32

static HANDLE  s_image_file    = INVALID_HANDLE_VALUE;
static HANDLE  s_bitmap_file   = INVALID_HANDLE_VALUE;
static HANDLE  s_image_mapping = nullptr;
static HANDLE  s_bitmap_mapping = nullptr;
static uint8_t* s_image_map    = nullptr;
static uint8_t* s_bitmap_map   = nullptr;

#else // POSIX

static int      s_image_fd   = -1;
static int      s_bitmap_fd  = -1;
static uint8_t* s_image_map  = nullptr;
static uint8_t* s_bitmap_map = nullptr;

#endif

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Derive the bitmap path by appending ".bitmap" to the image path.
static std::string bitmap_path_for(const char* filepath)
{
	return std::string(filepath) + ".bitmap";
}

#ifdef _WIN32

// Create (or truncate) a file, pre-fill it with zeros to `size` bytes,
// and return an mmap'd pointer.  Returns nullptr on failure.
static uint8_t* win32_map_file(const char* path,
                                uint32_t    size,
                                HANDLE&     out_file,
                                HANDLE&     out_mapping)
{
	out_file = CreateFileA(path,
	                       GENERIC_READ | GENERIC_WRITE,
	                       0,        // no sharing
	                       nullptr,  // default security
	                       CREATE_ALWAYS,
	                       FILE_ATTRIBUTE_NORMAL,
	                       nullptr);
	if (out_file == INVALID_HANDLE_VALUE) {
		fprintf(stderr,
		        "[debugtrace] WARNING: cannot create file '%s' (error %lu)\n",
		        path, GetLastError());
		return nullptr;
	}

	// Extend the file to the required size (pre-filled with zeros by the OS).
	LARGE_INTEGER li;
	li.QuadPart = static_cast<LONGLONG>(size);
	if (!SetFilePointerEx(out_file, li, nullptr, FILE_BEGIN) ||
	    !SetEndOfFile(out_file)) {
		fprintf(stderr,
		        "[debugtrace] WARNING: cannot resize file '%s' (error %lu)\n",
		        path, GetLastError());
		CloseHandle(out_file);
		out_file = INVALID_HANDLE_VALUE;
		return nullptr;
	}

	out_mapping = CreateFileMappingA(out_file,
	                                  nullptr,
	                                  PAGE_READWRITE,
	                                  0,
	                                  size,
	                                  nullptr);
	if (!out_mapping) {
		fprintf(stderr,
		        "[debugtrace] WARNING: cannot map file '%s' (error %lu)\n",
		        path, GetLastError());
		CloseHandle(out_file);
		out_file = INVALID_HANDLE_VALUE;
		return nullptr;
	}

	auto* ptr = static_cast<uint8_t*>(
	        MapViewOfFile(out_mapping, FILE_MAP_ALL_ACCESS, 0, 0, size));
	if (!ptr) {
		fprintf(stderr,
		        "[debugtrace] WARNING: MapViewOfFile failed for '%s' (error %lu)\n",
		        path, GetLastError());
		CloseHandle(out_mapping);
		out_mapping = nullptr;
		CloseHandle(out_file);
		out_file = INVALID_HANDLE_VALUE;
	}
	return ptr;
}

static void win32_unmap_file(uint8_t*& ptr,
                              HANDLE&  mapping,
                              HANDLE&  file,
                              uint32_t size)
{
	if (ptr) {
		FlushViewOfFile(ptr, size);
		UnmapViewOfFile(ptr);
		ptr = nullptr;
	}
	if (mapping) {
		CloseHandle(mapping);
		mapping = nullptr;
	}
	if (file != INVALID_HANDLE_VALUE) {
		FlushFileBuffers(file);
		CloseHandle(file);
		file = INVALID_HANDLE_VALUE;
	}
}

#else // POSIX

// Create (or truncate) a file, pre-fill it with zeros to `size` bytes,
// and return an mmap'd pointer.  Returns nullptr on failure.
static uint8_t* posix_map_file(const char* path, uint32_t size, int& out_fd)
{
	out_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (out_fd < 0) {
		fprintf(stderr,
		        "[debugtrace] WARNING: cannot open file '%s'\n", path);
		return nullptr;
	}

	// Extend the file to the required size.  ftruncate zero-fills any
	// new space, giving us our pre-zeroed image for free.
	if (ftruncate(out_fd, static_cast<off_t>(size)) != 0) {
		fprintf(stderr,
		        "[debugtrace] WARNING: cannot resize file '%s'\n", path);
		close(out_fd);
		out_fd = -1;
		return nullptr;
	}

	void* ptr = mmap(nullptr, size,
	                  PROT_READ | PROT_WRITE, MAP_SHARED,
	                  out_fd, 0);
	if (ptr == MAP_FAILED) {
		fprintf(stderr,
		        "[debugtrace] WARNING: mmap failed for '%s'\n", path);
		close(out_fd);
		out_fd = -1;
		return nullptr;
	}
	return static_cast<uint8_t*>(ptr);
}

static void posix_unmap_file(uint8_t*& ptr, int& fd, uint32_t size)
{
	if (ptr) {
		msync(ptr, size, MS_SYNC);
		munmap(ptr, size);
		ptr = nullptr;
	}
	if (fd >= 0) {
		close(fd);
		fd = -1;
	}
}

#endif // _WIN32

// ---------------------------------------------------------------------------
// Public implementation
// ---------------------------------------------------------------------------

void OpcodeDump_Init(const char* filepath)
{
	// Close any previously-open mappings so init is safe to call more than once.
	OpcodeDump_Shutdown();

	if (!filepath || filepath[0] == '\0') {
		return;
	}

	const std::string bmap_path = bitmap_path_for(filepath);

#ifdef _WIN32
	s_image_map  = win32_map_file(filepath,
	                               PHYS_ADDR_SPACE,
	                               s_image_file,
	                               s_image_mapping);
	if (!s_image_map) {
		return;
	}
	s_bitmap_map = win32_map_file(bmap_path.c_str(),
	                               BITMAP_SIZE,
	                               s_bitmap_file,
	                               s_bitmap_mapping);
	if (!s_bitmap_map) {
		win32_unmap_file(s_image_map, s_image_mapping, s_image_file, PHYS_ADDR_SPACE);
	}
#else
	s_image_map = posix_map_file(filepath, PHYS_ADDR_SPACE, s_image_fd);
	if (!s_image_map) {
		return;
	}
	s_bitmap_map = posix_map_file(bmap_path.c_str(), BITMAP_SIZE, s_bitmap_fd);
	if (!s_bitmap_map) {
		posix_unmap_file(s_image_map, s_image_fd, PHYS_ADDR_SPACE);
	}
#endif
}

void OpcodeDump_Shutdown()
{
#ifdef _WIN32
	win32_unmap_file(s_bitmap_map, s_bitmap_mapping, s_bitmap_file, BITMAP_SIZE);
	win32_unmap_file(s_image_map,  s_image_mapping,  s_image_file,  PHYS_ADDR_SPACE);
#else
	posix_unmap_file(s_bitmap_map, s_bitmap_fd, BITMAP_SIZE);
	posix_unmap_file(s_image_map,  s_image_fd,  PHYS_ADDR_SPACE);
#endif
}

void OpcodeDump_Write(uint32_t phys_ip, int num_bytes)
{
	if (!s_image_map || !s_bitmap_map || num_bytes <= 0) {
		return;
	}

	// Write each instruction byte into the flat image at its exact physical
	// address offset.  Idempotent: re-executing the same address writes the
	// same bytes to the same location.
	for (int i = 0; i < num_bytes; ++i) {
		const uint32_t addr = (phys_ip + static_cast<uint32_t>(i)) & 0xFFFFF;
		s_image_map[addr] = mem_readb(addr);
	}

	// Mark the instruction start address in the coverage bitmap.
	const uint32_t start = phys_ip & 0xFFFFF;
	s_bitmap_map[start / 8u] |= static_cast<uint8_t>(1u << (start % 8u));
}
