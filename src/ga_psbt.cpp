#include "ga_psbt.hpp"
#include "exception.hpp"
#include "ga_tx.hpp"
#include "logging.hpp"
#include "session_impl.hpp"

#include <nlohmann/json.hpp>

#define BUILD_ELEMENTS
#include <wally_psbt.h>
#include <wally_psbt_members.h>

namespace ga {
namespace sdk {
    void Psbt::psbt_deleter::operator()(struct wally_psbt* p) { wally_psbt_free(p); }

    Psbt::Psbt(const std::string& psbt_base64, bool is_liquid)
        : m_original_version(0)
        , m_is_liquid(is_liquid)
    {
        struct wally_psbt* p;
        constexpr uint32_t b64_flags = 0;
        GDK_VERIFY(wally_psbt_from_base64(psbt_base64.c_str(), b64_flags, &p));
        m_psbt.reset(p);
        size_t val;
        GDK_VERIFY(wally_psbt_is_elements(m_psbt.get(), &val));
        if (m_is_liquid != !!val) {
            throw user_error("PSBT/PSET mismatch");
        }
        GDK_VERIFY(wally_psbt_get_version(m_psbt.get(), &val));
        m_original_version = static_cast<uint32_t>(val);
        // Upgrade to version 2 so our processing in gdk is identical
        constexpr uint32_t ver_flags = 0;
        GDK_VERIFY(wally_psbt_set_version(m_psbt.get(), ver_flags, WALLY_PSBT_VERSION_2));
    }

    Psbt::~Psbt() {}

    void Psbt::swap(Psbt& rhs)
    {
        std::swap(m_is_liquid, rhs.m_is_liquid);
        std::swap(m_original_version, rhs.m_original_version);
        std::swap(m_psbt, rhs.m_psbt);
    }

    Tx Psbt::extract() const
    {
        struct wally_tx* p;
        GDK_VERIFY(wally_psbt_extract(m_psbt.get(), WALLY_PSBT_EXTRACT_NON_FINAL, &p));
        return Tx(p, m_is_liquid);
    }

    std::string Psbt::to_base64(bool include_redundant) const
    {
        std::unique_ptr<struct wally_psbt> tmp;
        struct wally_psbt* psbt = m_psbt.get();
        if (m_original_version != WALLY_PSBT_VERSION_2) {
            // Clone and downgrade the PSBT
            constexpr uint32_t clone_flags = 0, ver_flags = 0;
            GDK_VERIFY(wally_psbt_clone_alloc(psbt, clone_flags, &psbt));
            tmp.reset(psbt);
            GDK_VERIFY(wally_psbt_set_version(psbt, ver_flags, m_original_version));
        }
        const uint32_t b64_flags = include_redundant ? WALLY_PSBT_SERIALIZE_FLAG_REDUNDANT : 0;
        char* output = nullptr;
        GDK_VERIFY(wally_psbt_to_base64(psbt, b64_flags, &output));
        wally_string_ptr tmp_str(output);
        return std::string(tmp_str.get());
    }

    size_t Psbt::get_num_inputs() const { return m_psbt->num_inputs; }

    uint32_t Psbt::get_input_sighash(size_t index) const
    {
        size_t written;
        GDK_VERIFY(wally_psbt_get_input_sighash(m_psbt.get(), index, &written));
        return written & 0xffffffffu;
    }

    void Psbt::set_input_finalization_data(size_t index, const Tx& tx)
    {
        const auto& txin = tx.get_input(index);
        GDK_VERIFY(wally_psbt_set_input_final_witness(m_psbt.get(), index, txin.witness));
        GDK_VERIFY(wally_psbt_set_input_final_scriptsig(m_psbt.get(), index, txin.script, txin.script_len));
    }

    nlohmann::json Psbt::get_details(session_impl& session, nlohmann::json details) const
    {
        const Tx tx(extract());

        nlohmann::json::array_t inputs;
        inputs.reserve(tx.get_num_inputs());
        for (const auto& tx_in : tx.get_inputs()) {
            const std::string txhash_hex = b2h_rev(tx_in.txhash);
            const uint32_t vout = tx_in.index;
            for (const auto& utxo : details.at("utxos")) {
                if (utxo.value("txhash", std::string()) == txhash_hex && utxo.at("pt_idx") == vout) {
                    inputs.emplace_back(std::move(utxo));
                    break;
                }
            }
        }

        nlohmann::json::array_t outputs;
        outputs.reserve(tx.get_num_outputs());
        for (size_t i = 0; i < tx.get_num_outputs(); ++i) {
            const auto& o = tx.get_output(i);
            if (!o.script_len) {
                continue; // Liquid fee
            }
            auto output_data = session.get_scriptpubkey_data({ o.script, o.script_len });
            if (output_data.empty()) {
                continue; // Scriptpubkey does not belong the wallet
            }
            if (m_is_liquid) {
                const auto unblinded = unblind_output(session, tx, i);
                if (unblinded.contains("error")) {
                    GDK_LOG_SEV(log_level::warning) << "output " << i << ": " << unblinded.at("error");
                    continue; // Failed to unblind
                }
                output_data.update(unblinded);
            }
            outputs.emplace_back(output_data);
        }

        return { { "inputs", std::move(inputs) }, { "outputs", std::move(outputs) } };
    }

} // namespace sdk
} // namespace ga
