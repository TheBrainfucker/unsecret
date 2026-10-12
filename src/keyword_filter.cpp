#include "unsecret/keyword_filter.hpp"

#include <queue>
#include <stdexcept>

namespace unsecret {

namespace {

constexpr std::uint32_t none = 0xFFFFFFFF;

unsigned char lower(char c) {
    const auto u = static_cast<unsigned char>(c);
    return (u >= 'A' && u <= 'Z') ? static_cast<unsigned char>(u + ('a' - 'A')) : u;
}

}  // namespace

KeywordFilter::KeywordFilter(const std::vector<std::pair<std::string, std::size_t>>& keywords) {
    State root;
    root.next.fill(none);
    states_.push_back(root);

    // 1. A trie of the lowercased keywords.
    for (const auto& [keyword, group] : keywords) {
        if (group >= max_groups) {
            throw std::out_of_range("keyword group must be below 64");
        }
        if (keyword.empty()) {
            throw std::invalid_argument("empty keyword");
        }
        std::uint32_t s = 0;
        for (const char c : keyword) {
            const auto byte = lower(c);
            if (states_[s].next[byte] == none) {
                State child;
                child.next.fill(none);
                states_.push_back(child);
                states_[s].next[byte] = static_cast<std::uint32_t>(states_.size() - 1);
            }
            s = states_[s].next[byte];
        }
        states_[s].groups |= std::uint64_t{1} << group;
    }

    // 2. Fill every missing edge from the fallback state (breadth first),
    // so find() is one table lookup per byte.
    std::vector<std::uint32_t> fallback(states_.size(), 0);
    std::queue<std::uint32_t> queue;
    for (auto& next : states_[0].next) {
        if (next == none) {
            next = 0;
        } else {
            queue.push(next);
        }
    }
    while (!queue.empty()) {
        const auto s = queue.front();
        queue.pop();
        states_[s].groups |= states_[fallback[s]].groups;
        for (std::size_t byte = 0; byte < 256; ++byte) {
            auto& next = states_[s].next[byte];
            const auto via_fallback = states_[fallback[s]].next[byte];
            if (next == none) {
                next = via_fallback;
            } else {
                fallback[next] = via_fallback;
                queue.push(next);
            }
        }
    }
}

std::uint64_t KeywordFilter::find(std::string_view text) const {
    if (states_.empty()) {
        return 0;
    }
    std::uint64_t groups = 0;
    std::uint32_t s = 0;
    for (const char c : text) {
        s = states_[s].next[lower(c)];
        groups |= states_[s].groups;
    }
    return groups;
}

}  // namespace unsecret
