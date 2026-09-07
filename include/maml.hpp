// maml - byte-pattern matching for binaries, with a seed-then-refine scanner
// SPDX-License-Identifier: BSL-1.0 OR MIT
//
// Convenience umbrella. Including <maml/maml.hpp> and
// <maml/mamlscan.hpp> directly is equally fine -- mamlscan.hpp pulls in the
// matcher itself, so either header stands alone.
//
// NOTE the guard name. `maml/maml.hpp` already uses MAML_HPP, so
// an umbrella claiming the same guard silently suppresses the header it is
// supposed to be including: the core body is skipped, and the failure surfaces
// as a wall of "undeclared identifier" errors inside mamlscan.hpp, nowhere near
// the cause.

#ifndef MAML_UMBRELLA_HPP
#define MAML_UMBRELLA_HPP

// The matcher: compiles a pattern string and tests it at an address.
#include "maml/maml.hpp"

// The scanner: finds every match in an image, seeding on the rarest literal
// run rather than scanning for the first byte.
#include "maml/mamlscan.hpp"

#endif // MAML_UMBRELLA_HPP
