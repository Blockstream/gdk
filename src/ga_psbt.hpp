#ifndef GDK_GA_PSBT_HPP
#define GDK_GA_PSBT_HPP
#pragma once

#include <memory>
#include <set>
#include <string>

#include <nlohmann/json_fwd.hpp>

struct wally_psbt;
struct wally_psbt_input;
struct wally_psbt_output;

namespace green {

    class session_impl;
    class Tx;

    class Psbt {
    public:
        Psbt(const std::string& psbt_base64, bool is_liquid);
        Psbt(session_impl& session, const nlohmann::json& details, bool is_liquid);
        ~Psbt();

        Psbt(Psbt&& rhs) = default;
        Psbt(Psbt& rhs) = delete;
        Psbt(const Psbt& rhs) = delete;

        void swap(Psbt& rhs);

        std::string to_base64(bool include_redundant) const;
        nlohmann::json to_json(session_impl& session, nlohmann::json utxos) const;

        std::vector<unsigned char> get_genesis_blockhash() const;

        // Finalize the PSBT for extraction.
        // if allow_partial is false, throws if any finalization data is
        // missing and/or the PSBT cannot be fully finalized.
        void finalize(bool allow_partial = false);

        Tx extract() const;

        nlohmann::json get_details(session_impl& session, nlohmann::json details) const;

        // Inputs
        size_t get_num_inputs() const;
        struct wally_psbt_input& get_input(size_t index);
        const struct wally_psbt_input& get_input(size_t index) const;

        // Add any valid signatures from the tx input at 'index' to the PSBT
        void set_input_signatures(session_impl& session, const nlohmann::json& utxo, const Tx& tx, size_t index);

        // Outputs
        size_t get_num_outputs() const;
        struct wally_psbt_output& get_output(size_t index);
        const struct wally_psbt_output& get_output(size_t index) const;

    private:
        std::pair<nlohmann::json, std::set<std::string>> inputs_to_json(
            session_impl& session, Tx& tx, nlohmann::json utxos) const;
        nlohmann::json outputs_to_json(
            session_impl& session, const Tx& tx, const std::set<std::string>& wallet_assets) const;
        void from_json(session_impl& session, const nlohmann::json& details);

        struct psbt_deleter {
            void operator()(struct wally_psbt* p);
        };
        std::unique_ptr<struct wally_psbt, psbt_deleter> m_psbt;
        uint32_t m_original_version;
        bool m_is_liquid;
    };

} // namespace green

#endif
