#ifndef GDK_GA_PSBT_HPP
#define GDK_GA_PSBT_HPP
#pragma once

#include <memory>
#include <string>

#include <nlohmann/json_fwd.hpp>

struct wally_psbt;

namespace ga {
namespace sdk {
    class session_impl;
    class Tx;

    class Psbt {
    public:
        Psbt(const std::string& psbt_base64, bool is_liquid);
        ~Psbt();

        Psbt(Psbt&& rhs) = default;
        Psbt(Psbt& rhs) = delete;
        Psbt(const Psbt& rhs) = delete;

        void swap(Psbt& rhs);

        std::string to_base64(bool include_redundant) const;

        Tx extract() const;

        nlohmann::json get_details(session_impl& session, nlohmann::json details) const;

        // Inputs
        size_t get_num_inputs() const;
        uint32_t get_input_sighash(size_t index) const;

        // Finalize the input using the witness and scriptsig from a fully signed tx.
        // Unlike normal finalization, this does not remove the source fields.
        void set_input_finalization_data(size_t index, const Tx& tx);

    private:
        struct psbt_deleter {
            void operator()(struct wally_psbt* p);
        };
        std::unique_ptr<struct wally_psbt, psbt_deleter> m_psbt;
        uint32_t m_original_version;
        bool m_is_liquid;
    };

} // namespace sdk
} // namespace ga

#endif
