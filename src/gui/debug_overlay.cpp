// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Host-only text-cell grid for RE / agents.
// Drawn after the guest framebuffer texture. Never writes guest VRAM —
// B800 / mem dumps stay pure. Window screenshots and post-render capture
// will show the grid.

#include "debug_overlay.h"

#include "config/setup.h"
#include "gui/mapper.h"
#include "hardware/memory.h"
#include "misc/logging.h"

#include "SDL.h"

// Glad after SDL (OpenGL path optional at link time — always available in this fork)
#include "glad/gl.h"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <string>
#include <vector>

namespace {

struct Cfg {
	bool enabled_at_start = false;
	int force_cols        = 0; // 0 = BIOS
	int force_rows        = 0;
	int major_every       = 5;
	uint8_t r             = 0;
	uint8_t g             = 220;
	uint8_t b             = 80;
	uint8_t a             = 140;
	uint8_t major_a       = 220;
	std::string hotkey    = "ctrl+alt+g";
};

Cfg g_cfg{};
bool g_visible = false;
bool g_inited  = false;

constexpr uint16_t kBiosSeg    = 0x40;
constexpr uint16_t kBiosNbCols = 0x4a;
constexpr uint16_t kBiosNbRows = 0x84; // rows - 1

void resolve_grid(int& cols, int& rows)
{
	if (g_cfg.force_cols > 0 && g_cfg.force_rows > 0) {
		cols = g_cfg.force_cols;
		rows = g_cfg.force_rows;
		return;
	}

	cols = static_cast<int>(real_readw(kBiosSeg, kBiosNbCols));
	rows = static_cast<int>(real_readb(kBiosSeg, kBiosNbRows)) + 1;

	if (cols < 40 || cols > 132) {
		cols = 80;
	}
	if (rows < 15 || rows > 60) {
		rows = 25;
	}
}

void toggle_hotkey(bool pressed)
{
	if (!pressed || !g_inited) {
		return;
	}
	DEBUG_OVERLAY_Toggle();
	int c = 0;
	int r = 0;
	resolve_grid(c, r);
	LOG_MSG("DEBUG_OVERLAY: grid %s (%dx%d cells, host-only — VRAM pure)",
	        g_visible ? "ON" : "OFF",
	        c,
	        r);
}

bool parse_hotkey(const std::string& spec, SDL_Scancode& key, uint32_t& mods)
{
	key  = SDL_SCANCODE_UNKNOWN;
	mods = 0;
	if (spec.empty() || spec == "none" || spec == "off" || spec == "false") {
		return false;
	}

	std::string s = spec;
	for (auto& ch : s) {
		ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
	}

	size_t start = 0;
	for (size_t i = 0; i <= s.size(); ++i) {
		if (i != s.size() && s[i] != '+') {
			continue;
		}
		std::string t = s.substr(start, i - start);
		while (!t.empty() && t.front() == ' ') {
			t.erase(t.begin());
		}
		while (!t.empty() && t.back() == ' ') {
			t.pop_back();
		}
		start = i + 1;
		if (t.empty()) {
			continue;
		}
		if (t == "ctrl" || t == "control") {
			mods |= MMOD1;
		} else if (t == "alt") {
			mods |= MMOD2;
		} else if (t.size() >= 2 && t[0] == 'f') {
			int n = 0;
			try {
				n = std::stoi(t.substr(1));
			} catch (...) {
				n = 0;
			}
			if (n >= 1 && n <= 12) {
				key = static_cast<SDL_Scancode>(SDL_SCANCODE_F1 +
				                                (n - 1));
			}
		} else if (t.size() == 1 && t[0] >= 'a' && t[0] <= 'z') {
			key = static_cast<SDL_Scancode>(SDL_SCANCODE_A + (t[0] - 'a'));
		}
	}
	return key != SDL_SCANCODE_UNKNOWN;
}

} // namespace

void DEBUG_OVERLAY_AddConfigSection(const ConfigPtr& conf)
{
	assert(conf);
	using enum Property::Changeable::Value;

	auto* sec = conf->AddSection("debugoverlay");

	auto* pbool = sec->AddBool("enabled", OnlyAtStart, false);
	pbool->SetHelp(
	        "Show host-side text-cell grid overlay at startup ('false' by default).\n"
	        "Drawn on the window only — guest VRAM / B800 dumps are never modified.");

	auto* pstring = sec->AddString("hotkey", OnlyAtStart, "ctrl+alt+g");
	pstring->SetHelp(
	        "Toggle overlay hotkey, e.g. 'ctrl+alt+g', 'f8', 'none' ('ctrl+alt+g' by default).");

	auto* pint = sec->AddInt("force_cols", OnlyAtStart, 0);
	pint->SetMinMax(0, 132);
	pint->SetHelp(
	        "Force grid columns (0 = BIOS text cols). Use 40 for ICON mode 01h.");

	pint = sec->AddInt("force_rows", OnlyAtStart, 0);
	pint->SetMinMax(0, 60);
	pint->SetHelp(
	        "Force grid rows (0 = BIOS text rows). Use 25 for ICON mode 01h.");

	pint = sec->AddInt("major_every", OnlyAtStart, 5);
	pint->SetMinMax(0, 40);
	pint->SetHelp("Thicken every Nth line (0 = all equal; 5 by default).");
}

void DEBUG_OVERLAY_Init()
{
	auto* sec = get_section("debugoverlay");
	if (!sec) {
		return;
	}

	g_cfg.enabled_at_start = sec->GetBool("enabled");
	g_cfg.hotkey           = sec->GetString("hotkey");
	g_cfg.force_cols       = sec->GetInt("force_cols");
	g_cfg.force_rows       = sec->GetInt("force_rows");
	g_cfg.major_every      = sec->GetInt("major_every");
	g_visible              = g_cfg.enabled_at_start;
	g_inited               = true;

	SDL_Scancode key = SDL_SCANCODE_UNKNOWN;
	uint32_t mods    = 0;
	if (parse_hotkey(g_cfg.hotkey, key, mods)) {
		MAPPER_AddHandler(toggle_hotkey, key, mods, "dbgoverlay",
		                  "Debug Overlay");
	}

	int c = 0;
	int r = 0;
	resolve_grid(c, r);
	LOG_MSG("DEBUG_OVERLAY: init visible=%s grid~%dx%d force=%d,%d hotkey=%s "
	        "(host-only)",
	        g_visible ? "true" : "false",
	        c,
	        r,
	        g_cfg.force_cols,
	        g_cfg.force_rows,
	        g_cfg.hotkey.c_str());
}

void DEBUG_OVERLAY_Shutdown()
{
	g_inited  = false;
	g_visible = false;
}

void DEBUG_OVERLAY_SetEnabled(bool on)
{
	g_visible = on && g_inited;
}

bool DEBUG_OVERLAY_IsEnabled()
{
	return g_visible;
}

void DEBUG_OVERLAY_Toggle()
{
	if (!g_inited) {
		return;
	}
	g_visible = !g_visible;
}

void DEBUG_OVERLAY_GetGrid(int& cols, int& rows)
{
	resolve_grid(cols, rows);
}

void DEBUG_OVERLAY_DrawSdl(SDL_Renderer* renderer)
{
	if (!g_visible || !renderer || !g_inited) {
		return;
	}

	int cols = 0;
	int rows = 0;
	resolve_grid(cols, rows);
	if (cols < 1 || rows < 1) {
		return;
	}

	// Relative to current SDL viewport (= game draw rect).
	SDL_Rect vp{};
	SDL_RenderGetViewport(renderer, &vp);
	if (vp.w <= 1 || vp.h <= 1) {
		return;
	}

	const float cell_w = static_cast<float>(vp.w) / static_cast<float>(cols);
	const float cell_h = static_cast<float>(vp.h) / static_cast<float>(rows);

	Uint8 pr = 0;
	Uint8 pg = 0;
	Uint8 pb = 0;
	Uint8 pa = 0;
	SDL_GetRenderDrawColor(renderer, &pr, &pg, &pb, &pa);
	SDL_BlendMode prev_mode = SDL_BLENDMODE_NONE;
	SDL_GetRenderDrawBlendMode(renderer, &prev_mode);
	SDL_SetRenderDrawBlendMode(renderer, SDL_BLENDMODE_BLEND);

	const int maj = g_cfg.major_every;

	for (int c = 0; c <= cols; ++c) {
		const bool major = (maj > 0) && (c % maj == 0);
		const int x = static_cast<int>(static_cast<float>(c) * cell_w + 0.5f);
		SDL_SetRenderDrawColor(renderer,
		                       g_cfg.r,
		                       g_cfg.g,
		                       g_cfg.b,
		                       major ? g_cfg.major_a : g_cfg.a);
		SDL_RenderDrawLine(renderer, x, 0, x, vp.h - 1);
		if (major && x + 1 < vp.w) {
			SDL_RenderDrawLine(renderer, x + 1, 0, x + 1, vp.h - 1);
		}
	}
	for (int r = 0; r <= rows; ++r) {
		const bool major = (maj > 0) && (r % maj == 0);
		const int y = static_cast<int>(static_cast<float>(r) * cell_h + 0.5f);
		SDL_SetRenderDrawColor(renderer,
		                       g_cfg.r,
		                       g_cfg.g,
		                       g_cfg.b,
		                       major ? g_cfg.major_a : g_cfg.a);
		SDL_RenderDrawLine(renderer, 0, y, vp.w - 1, y);
		if (major && y + 1 < vp.h) {
			SDL_RenderDrawLine(renderer, 0, y + 1, vp.w - 1, y + 1);
		}
	}

	// Yellow origin mark (0,0 cell corner) for counting steps.
	SDL_SetRenderDrawColor(renderer, 255, 255, 0, 220);
	const int ox = std::max(3, static_cast<int>(cell_w / 3));
	const int oy = std::max(3, static_cast<int>(cell_h / 3));
	SDL_RenderDrawLine(renderer, 1, 1, ox, 1);
	SDL_RenderDrawLine(renderer, 1, 1, 1, oy);

	SDL_SetRenderDrawBlendMode(renderer, prev_mode);
	SDL_SetRenderDrawColor(renderer, pr, pg, pb, pa);
}

// ---------------------------------------------------------------------------
// OpenGL 3.3 core: tiny line shader (lazy init)
// ---------------------------------------------------------------------------

namespace {

GLuint g_gl_prog  = 0;
GLuint g_gl_vao   = 0;
GLuint g_gl_vbo   = 0;
bool g_gl_ok      = false;
bool g_gl_tried   = false;

const char* k_vs = R"(#version 330 core
layout(location = 0) in vec2 a_pos;
void main() {
	gl_Position = vec4(a_pos, 0.0, 1.0);
}
)";

const char* k_fs = R"(#version 330 core
uniform vec4 u_color;
out vec4 frag;
void main() {
	frag = u_color;
}
)";

GLuint compile_shader(const GLenum type, const char* src)
{
	const GLuint s = glCreateShader(type);
	glShaderSource(s, 1, &src, nullptr);
	glCompileShader(s);
	GLint ok = 0;
	glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
	if (!ok) {
		char log[512];
		glGetShaderInfoLog(s, sizeof(log), nullptr, log);
		LOG_ERR("DEBUG_OVERLAY: shader compile failed: %s", log);
		glDeleteShader(s);
		return 0;
	}
	return s;
}

bool ensure_gl()
{
	if (g_gl_tried) {
		return g_gl_ok;
	}
	g_gl_tried = true;

	const GLuint vs = compile_shader(GL_VERTEX_SHADER, k_vs);
	const GLuint fs = compile_shader(GL_FRAGMENT_SHADER, k_fs);
	if (!vs || !fs) {
		return false;
	}
	g_gl_prog = glCreateProgram();
	glAttachShader(g_gl_prog, vs);
	glAttachShader(g_gl_prog, fs);
	glLinkProgram(g_gl_prog);
	glDeleteShader(vs);
	glDeleteShader(fs);
	GLint ok = 0;
	glGetProgramiv(g_gl_prog, GL_LINK_STATUS, &ok);
	if (!ok) {
		LOG_ERR("DEBUG_OVERLAY: program link failed");
		glDeleteProgram(g_gl_prog);
		g_gl_prog = 0;
		return false;
	}

	glGenVertexArrays(1, &g_gl_vao);
	glGenBuffers(1, &g_gl_vbo);
	glBindVertexArray(g_gl_vao);
	glBindBuffer(GL_ARRAY_BUFFER, g_gl_vbo);
	glBufferData(GL_ARRAY_BUFFER, 4096 * sizeof(float), nullptr, GL_DYNAMIC_DRAW);
	glEnableVertexAttribArray(0);
	glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, nullptr);
	glBindVertexArray(0);
	glBindBuffer(GL_ARRAY_BUFFER, 0);

	g_gl_ok = true;
	LOG_MSG("DEBUG_OVERLAY: OpenGL line path ready");
	return true;
}

void gl_draw_lines(const std::vector<float>& xy, const float r, const float g,
                   const float b, const float a)
{
	if (xy.size() < 4) {
		return;
	}
	glUseProgram(g_gl_prog);
	const GLint loc = glGetUniformLocation(g_gl_prog, "u_color");
	glUniform4f(loc, r, g, b, a);
	glBindVertexArray(g_gl_vao);
	glBindBuffer(GL_ARRAY_BUFFER, g_gl_vbo);
	glBufferSubData(GL_ARRAY_BUFFER,
	                0,
	                static_cast<GLsizeiptr>(xy.size() * sizeof(float)),
	                xy.data());
	glDrawArrays(GL_LINES, 0, static_cast<GLsizei>(xy.size() / 2));
	glBindVertexArray(0);
	glUseProgram(0);
}

} // namespace

void DEBUG_OVERLAY_DrawOpenGL()
{
	if (!g_visible || !g_inited) {
		return;
	}
	if (!ensure_gl()) {
		return;
	}

	int cols = 0;
	int rows = 0;
	resolve_grid(cols, rows);
	if (cols < 1 || rows < 1) {
		return;
	}

	// NDC over current glViewport (game draw rect).
	auto nx = [&](const int c) -> float {
		return -1.0f + 2.0f * static_cast<float>(c) / static_cast<float>(cols);
	};
	auto ny = [&](const int r) -> float {
		// GL NDC y is up; viewport still has y-up in clip after projection.
		// Screen row 0 is top → NDC y = +1
		return 1.0f - 2.0f * static_cast<float>(r) / static_cast<float>(rows);
	};

	std::vector<float> minor;
	std::vector<float> major;
	minor.reserve(static_cast<size_t>((cols + rows + 2) * 4));
	major.reserve(static_cast<size_t>((cols + rows + 2) * 4));

	const int maj = g_cfg.major_every;
	auto push = [](std::vector<float>& v, float x0, float y0, float x1, float y1) {
		v.push_back(x0);
		v.push_back(y0);
		v.push_back(x1);
		v.push_back(y1);
	};

	for (int c = 0; c <= cols; ++c) {
		const float x = nx(c);
		auto& dest = (maj > 0 && c % maj == 0) ? major : minor;
		push(dest, x, -1.0f, x, 1.0f);
	}
	for (int r = 0; r <= rows; ++r) {
		const float y = ny(r);
		auto& dest = (maj > 0 && r % maj == 0) ? major : minor;
		push(dest, -1.0f, y, 1.0f, y);
	}

	// Save/restore GL state lightly
	GLboolean blend_was = 0;
	glGetBooleanv(GL_BLEND, &blend_was);
	GLint depth_was = 0;
	glGetIntegerv(GL_DEPTH_TEST, &depth_was);
	glDisable(GL_DEPTH_TEST);
	glEnable(GL_BLEND);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

	const float rf = g_cfg.r / 255.0f;
	const float gf = g_cfg.g / 255.0f;
	const float bf = g_cfg.b / 255.0f;
	gl_draw_lines(minor, rf, gf, bf, g_cfg.a / 255.0f);
	gl_draw_lines(major, rf, gf, bf, g_cfg.major_a / 255.0f);

	// Origin marker (top-left)
	std::vector<float> origin = {
	        -1.0f, 1.0f, -1.0f + 2.0f / static_cast<float>(cols) * 0.35f, 1.0f,
	        -1.0f, 1.0f, -1.0f, 1.0f - 2.0f / static_cast<float>(rows) * 0.35f,
	};
	gl_draw_lines(origin, 1.0f, 1.0f, 0.0f, 0.9f);

	if (!blend_was) {
		glDisable(GL_BLEND);
	}
	if (depth_was) {
		glEnable(GL_DEPTH_TEST);
	}
}
