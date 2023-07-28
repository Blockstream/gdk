#ifndef GDK_GA_PSBT_HPP
#define GDK_GA_PSBT_HPP
#pragma once

#include <memory>
#include <string>

#include <nlohmann/json_fwd.hpp>

struct wally_psbt;
struct wally_psbt_input;
struct wally_psbt_output;

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
        nlohmann::json to_json(session_impl& session, nlohmann::json utxos) const;

        Tx extract() const;

        nlohmann::json get_details(session_impl& session, nlohmann::json details) const;

        // Inputs
        size_t get_num_inputs() const;
        struct wally_psbt_input& get_input(size_t index);
        const struct wally_psbt_input& get_input(size_t index) const;

        // Finalize the input using the witness and scriptsig from a fully signed tx.
        // Unlike normal finalization, this does not remove the source fields.
        void set_input_finalization_data(size_t index, const Tx& tx);

        // Outputs
        size_t get_num_outputs() const;
        struct wally_psbt_output& get_output(size_t index);
        const struct wally_psbt_output& get_output(size_t index) const;

    private:
        nlohmann::json inputs_to_json(session_impl& session, nlohmann::json utxos) const;
        nlohmann::json outputs_to_json(session_impl& session, const Tx& tx) const;

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
