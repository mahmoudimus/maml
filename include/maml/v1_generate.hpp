// SPDX-License-Identifier: BSL-1.0 OR MIT
#pragma once
#include "generate.hpp"

namespace maml::v1::generate {
    using Image = maml::generate::Image;
    using Strategy = maml::generate::Strategy;
    using Resolution = maml::generate::Resolution;
    struct Options {
        size_t max_len = 64;
        int want = 4;
        bool prefer_short = true, deep_anchor = true, nibble_wildcards = true;
    };
    struct Candidate {
        std::string pattern;
        Strategy strategy = Strategy::Body;
        uint64_t anchor_site = 0;
        int64_t anchor_delta = 0;
        std::string target_capture;
        std::string dialect = "maml-v1";
        size_t literals = 0;
    };
    namespace detail {
        inline maml::generate::Options options(const Options& opt) {
            if (opt.want < 0 || opt.want > 256 || opt.max_len < 1 || opt.max_len > 65536)
                throw Error("InvalidArgument", "want must be 0..256 and max_len must be 1..65536");
            return { opt.max_len, opt.want, opt.prefer_short, opt.deep_anchor, "maml-v1", opt.nibble_wildcards };
        }
        inline std::vector<Candidate> wrap(const std::vector<maml::generate::Candidate>& input) {
            std::vector<Candidate> out;
            for (const auto& c : input)
                out.push_back({ c.pattern, c.strategy, c.anchor_site, c.anchor_delta, c.target_capture, c.dialect, c.literals });
            return out;
        }
    } // namespace detail
    inline std::vector<Candidate> candidates(const Image& image, uint64_t target, const Options& opt = {}) {
        return detail::wrap(maml::generate::candidates(image, target, detail::options(opt)));
    }
    inline std::vector<Candidate> verified(const Image& a, uint64_t ta, const Image& b, uint64_t tb, const Options& opt = {}) {
        return detail::wrap(maml::generate::verified(a, ta, b, tb, detail::options(opt)));
    }
    inline std::vector<Resolution> resolve_consensus(std::span<const uint8_t> image, const std::vector<Candidate>& candidates) {
        std::vector<maml::generate::Candidate> input;
        for (const auto& c : candidates) {
            if (c.dialect != "maml-v1")
                throw Error("InvalidArgument", "Expected maml-v1 candidate");
            maml::generate::Candidate native;
            native.pattern = c.pattern;
            native.strategy = c.strategy;
            native.anchor_site = c.anchor_site;
            native.anchor_delta = c.anchor_delta;
            native.target_capture = c.target_capture;
            native.dialect = c.dialect;
            input.push_back(std::move(native));
        }
        return maml::generate::resolve_consensus(image, input);
    }
} // namespace maml::v1::generate
