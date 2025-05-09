#include "swap_auth_handlers.hpp"
#include "ga_auth_handlers.hpp"

#include "assertion.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "ga_wally.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "session.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "validate.hpp"
#include "xpub_hdkey.hpp"

namespace green {

    namespace {
        static const std::string LIQUIDEX_STR("liquidex_v1");
        static constexpr uint32_t LIQUIDEX_VERSION = 1;

        static void add_asset_utxos(
            const nlohmann::json& utxos, const std::string& asset_id, nlohmann::json::array_t& tx_inputs)
        {
            const auto p = utxos.find(asset_id);
            if (p != utxos.end()) {
                for (const auto& u : *p) {
                    tx_inputs.push_back(u);
                }
            }
        }

        static auto liquidex_get_fields(nlohmann::json& in_out)
        {
            nlohmann::json::array_t res;
            res.resize(in_out.size());
            for (size_t i = 0; i < in_out.size(); ++i) {
                res[i]["asset"] = std::move(in_out[i]["asset_id"]);
                const auto asset = j_rbytesref(res[i], "asset");
                res[i]["satoshi"] = std::move(in_out[i]["satoshi"]);
                const auto satoshi = j_amountref(res[i]).value();
                res[i]["asset_blinder"] = std::move(in_out[i]["assetblinder"]);
                const auto abf = j_rbytesref(res[i], "asset_blinder");
                const auto generator = asset_generator_from_bytes(asset, abf);
                const auto vbf = j_rbytesref(in_out[i], "amountblinder");
                const auto commitment = asset_value_commitment(satoshi, vbf, generator);
                const auto nonce = get_random_bytes<32>();
                try {
                    res[i]["value_blind_proof"] = b2h(explicit_rangeproof(satoshi, nonce, vbf, commitment, generator));
                } catch (const std::exception&) {
                    throw user_error("zero value or unblinded utxos cannot be swapped");
                }
                // This must be aggregated and removed
                res[i]["scalar"] = b2h(asset_scalar_offset(satoshi, abf, vbf));
            }
            return res;
        }

        static nlohmann::json::array_t liquidex_aggregate_scalars(
            nlohmann::json::array_t& inputs, nlohmann::json::array_t& outputs)
        {
            GDK_RUNTIME_ASSERT(inputs.size() == 1 && outputs.size() == 1);
            const auto input_scalar = j_bytesref(inputs[0], "scalar");
            const auto output_scalar = j_bytesref(outputs[0], "scalar");
            outputs[0].erase("scalar");
            inputs[0].erase("scalar");
            return { b2h(ec_scalar_subtract(input_scalar, output_scalar)) };
        }

        static nlohmann::json liquidex_get_maker_input(const Tx& tx, const nlohmann::json& proposal_input)
        {
            auto maker_input = tx.input_to_json(0);
            if (!maker_input.contains("witness")) {
                throw user_error("Maker input is not segwit");
            }
            if (!maker_input.contains("script_sig")) {
                maker_input["script_sig"] = std::string_view{};
            }
            maker_input["asset_id"] = proposal_input.at("asset");
            maker_input["assetblinder"] = proposal_input.at("asset_blinder");
            maker_input["satoshi"] = j_amountref(proposal_input).value();
            maker_input["skip_signing"] = true;
            return maker_input;
        }

        static nlohmann::json liquidex_get_maker_addressee(
            const network_parameters& net_params, const Tx& tx, const nlohmann::json& proposal_output)
        {
            GDK_RUNTIME_ASSERT(tx.get_num_outputs());
            const auto& tx_output = tx.get_output(0);
            const auto rangeproof = gsl::make_span(tx_output.rangeproof, tx_output.rangeproof_len);
            const auto commitment = gsl::make_span(tx_output.value, tx_output.value_len);
            const auto nonce = gsl::make_span(tx_output.nonce, tx_output.nonce_len);
            const auto scriptpubkey = gsl::make_span(tx_output.script, tx_output.script_len);

            nlohmann::json ret = { { "address", get_address_from_scriptpubkey(net_params, scriptpubkey) },
                { "is_confidential", false }, { "index", 0 }, { "nonce_commitment", b2h(nonce) },
                { "is_blinded", true }, { "index", 0 }, { "nonce_commitment", b2h(nonce) },
                { "commitment", b2h(commitment) }, { "range_proof", b2h(rangeproof) },
                { "asset_id", proposal_output.at("asset") }, { "assetblinder", proposal_output.at("asset_blinder") },
                { "satoshi", j_amountref(proposal_output).value() } };
            if (proposal_output.contains("blinding_nonce")) {
                ret["blinding_nonce"] = proposal_output["blinding_nonce"];
            }
            return ret;
        }

        static std::unique_ptr<Tx> liquidex_validate_proposal(const nlohmann::json& proposal)
        {
            constexpr bool is_liquid = true;
            GDK_RUNTIME_ASSERT_MSG(proposal.at("version") == LIQUIDEX_VERSION, "unknown version");
            GDK_RUNTIME_ASSERT_MSG(proposal.dump().length() < 20000, "proposal exceeds maximum length");
            const auto& proposal_input = j_arrayref(proposal, "inputs", 1).at(0);
            const auto& proposal_output = j_arrayref(proposal, "outputs", 1).at(0);
            const auto scalar = h2b(j_arrayref(proposal, "scalars", 1).at(0));
            GDK_RUNTIME_ASSERT_MSG(ec_scalar_verify(scalar), "invalid scalar");
            GDK_RUNTIME_ASSERT_MSG(
                proposal_input.at("asset") != proposal_output.at("asset"), "cannot swap the same asset");
            auto tx = std::make_unique<Tx>(j_strref(proposal, "transaction"), is_liquid);
            GDK_RUNTIME_ASSERT_MSG(
                tx->get_num_inputs() == 1 && tx->get_num_outputs() == 1, "unexpected number of inputs or outputs");

            // Verify unblinded values match the transaction commitments
            // TODO: obtain the previous output and verify the input commitments
            const auto output_asset = j_rbytesref(proposal_output, "asset");
            const auto output_abf = j_rbytesref(proposal_output, "asset_blinder");
            const auto output_value = j_amountref(proposal_output).value();
            const auto value_blind_proof = j_bytesref(proposal_output, "value_blind_proof");
            const auto output_asset_commitment = asset_generator_from_bytes(output_asset, output_abf);
            const auto& tx_output = tx->get_output(0);
            const auto output_value_commitment = gsl::make_span(tx_output.value, tx_output.value_len);

            bool have_matched_asset_commitment = tx_output.asset_len == output_asset_commitment.size()
                && !memcmp(tx_output.asset, output_asset_commitment.data(), tx_output.asset_len);
            GDK_RUNTIME_ASSERT_MSG(have_matched_asset_commitment, "unblinded asset does not match commitment");

            bool value_verifies = explicit_rangeproof_verify(
                value_blind_proof, output_value, output_value_commitment, output_asset_commitment);
            GDK_RUNTIME_ASSERT_MSG(value_verifies, "cannot verify unblinded value matches commitment");
            return tx;
        }
    } // namespace

    //
    // Create swap transaction
    //
    create_swap_transaction_call::create_swap_transaction_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "create_swap_transaction")
        , m_details(details)
        , m_is_signed(false)
    {
    }

    auth_handler::state_type create_swap_transaction_call::call_impl()
    {
        const auto& swap_type = j_strref(m_details, "swap_type");
        if (swap_type == "liquidex") {
            GDK_RUNTIME_ASSERT_MSG(j_strref(m_details, "input_type") == LIQUIDEX_STR, "unknown input_type");
            GDK_RUNTIME_ASSERT_MSG(j_strref(m_details, "output_type") == LIQUIDEX_STR, "unknown output_type");
            return liquidex_impl();
        }
        GDK_RUNTIME_ASSERT_MSG(false, "unknown swap_type");

        return state_type::error; // Unreachable
    }

    auth_handler::state_type create_swap_transaction_call::liquidex_impl()
    {
        const auto& liquidex_details = m_details.at(LIQUIDEX_STR);
        const auto& send = j_arrayref(liquidex_details, "send", 1).at(0);
        const auto& receive = j_arrayref(liquidex_details, "receive", 1).at(0);
        // TODO: We may wish to allow receiving to a different subaccount.
        //       For now, receive to the same subaccount we are sending from
        const auto pointer = j_uint32ref(send, "subaccount");

        if (m_receive_address.empty()) {
            // Fetch a new address to receive the swapped asset on
            // TODO: Further validate the inputs
            if (pointer != 0 && m_net_params.is_electrum()) {
                // Singlesig: Ensure the subaccount type is segwit v0.
                // We skip checking subaccount 0 which is always p2sh-p2wsh.
                // Note that segwit v1 (taproot) does not support liquidex
                // makers because the signature hash covers the output surjection
                // proof, which cannot be created without the takers input.
                const auto subaccount = m_session->get_subaccount(pointer);
                const auto& sa_type = j_strref(subaccount, "type");
                if (sa_type != address_type::p2sh_p2wpkh && sa_type != address_type::p2wpkh) {
                    throw_user_error("Unsupported subaccount type");
                }
            }
            const nlohmann::json addr_details = { { "subaccount", pointer } };
            add_next_handler(new get_receive_address_call(m_session_parent, addr_details));
            return state_type::make_call;
        }
        if (m_create_details.empty()) {
            // Call create_transaction to create the swap tx
            nlohmann::json addressee = std::move(m_receive_address);
            m_receive_address["used"] = true; // Make sure m_receive_address.empty() isn't true
            addressee.update(receive);
            nlohmann::json::array_t addressees{ std::move(addressee) };
            std::vector<nlohmann::json> tx_inputs{ send };
            nlohmann::json utxos{ { send.at("asset_id"), tx_inputs } };
            nlohmann::json create_details = { { "addressees", std::move(addressees) }, { "is_partial", true },
                { "utxo_strategy", "manual" }, { "utxos", utxos }, { "transaction_inputs", std::move(tx_inputs) } };
            add_next_handler(new create_transaction_call(m_session_parent, create_details));
            return state_type::make_call;
        }
        if (!j_str_is_empty(m_create_details, "error")) {
            m_result = std::move(m_create_details);
            return state_type::done; // Create/blind tx returned an error, do not attempt to sign
        }
        if (!j_bool_or_false(m_create_details, "is_blinded")) {
            // Call blind_transaction to blind the callers side
            add_next_handler(new blind_transaction_call(m_session_parent, std::move(m_create_details)));
            return state_type::make_call;
        }

        // Call sign_transaction to sign the callers side
        constexpr uint32_t sighash_flags = WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY;
        m_create_details.at("transaction_inputs").at(0)["user_sighash"] = sighash_flags;
        // For AMP, skip server signing for multisig. The taker will ask the
        // backend to sign the completed swap since AMP only signs SIGHASH_ALL
        const bool is_amp_tx = m_create_details.contains("blinding_nonces");
        m_create_details["sign_with"] = nlohmann::json::array_t{ is_amp_tx ? "user" : "all" };
        add_next_handler(new sign_transaction_call(m_session_parent, m_create_details));
        return state_type::done; // We are complete once tx signing is done
    }

    void create_swap_transaction_call::on_next_handler_complete(auth_handler* next_handler)
    {
        if (m_receive_address.empty()) {
            // Call result is our new receive address
            m_receive_address = std::move(next_handler->move_result());
        } else if (m_create_details.empty()) {
            // Call result is our created/blinded tx
            m_create_details = std::move(next_handler->move_result());
        } else if (!m_is_signed) {
            // Call result is our signed tx
            auto result = std::move(next_handler->move_result());
            // Create liquidex_v1 proposal to return
            auto& tx_inputs = result.at("transaction_inputs");
            auto& tx_outputs = result.at("transaction_outputs");
            nlohmann::json::array_t inputs = liquidex_get_fields(tx_inputs);
            nlohmann::json::array_t outputs = liquidex_get_fields(tx_outputs);
            nlohmann::json::array_t scalars = liquidex_aggregate_scalars(inputs, outputs);
            GDK_RUNTIME_ASSERT(!inputs[0].contains("scalar") && !outputs[0].contains("scalar"));
            auto proposal = nlohmann::json({ { "version", LIQUIDEX_VERSION },
                { "transaction", std::move(result["transaction"]) }, { "inputs", std::move(inputs) },
                { "outputs", std::move(outputs) }, { "scalars", std::move(scalars) } });
            if (auto p = result.find("blinding_nonces"); p != result.end()) {
                // AMP: Make the prevout script and blinding nonce available
                proposal["inputs"][0]["script"] = std::move(tx_inputs.at(0).at("prevout_script"));
                proposal["outputs"][0]["blinding_nonce"] = p->at(0);
            }
            m_result[LIQUIDEX_STR] = nlohmann::json::object();
            m_result[LIQUIDEX_STR]["proposal"] = std::move(proposal);
            m_result["error"] = std::string_view{};
            m_is_signed = true;
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "Unknown next handler called");
        }
    }

    //
    // Complete swap transaction
    //
    complete_swap_transaction_call::complete_swap_transaction_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "complete_swap_transaction")
        , m_details(details)
    {
    }

    auth_handler::state_type complete_swap_transaction_call::call_impl()
    {
        const auto& swap_type = j_strref(m_details, "swap_type");
        if (swap_type == "liquidex") {
            GDK_RUNTIME_ASSERT_MSG(j_strref(m_details, "input_type") == LIQUIDEX_STR, "unknown input_type");
            GDK_RUNTIME_ASSERT_MSG(j_strref(m_details, "output_type") == "transaction", "unknown output_type");
            GDK_RUNTIME_ASSERT(m_net_params.is_liquid());
            return liquidex_impl();
        }
        GDK_RUNTIME_ASSERT_MSG(false, "unknown swap_type");

        return state_type::error; // Unreachable
    }

    auth_handler::state_type complete_swap_transaction_call::liquidex_impl()
    {
        // TODO: allow to take multiple proposal at once
        const auto& proposal = j_arrayref(m_details.at(LIQUIDEX_STR), "proposals", 1).at(0);
        if (!m_tx) {
            m_tx = liquidex_validate_proposal(proposal);
        }
        const auto& proposal_input = proposal.at("inputs").at(0);
        const std::string maker_asset_id = proposal_input.at("asset");
        const auto& proposal_output = proposal.at("outputs").at(0);
        const std::string taker_asset_id = proposal_output.at("asset");
        const auto& utxos = m_details.at("utxos");
        // Get the subaccount from the first taker_asset_id utxo
        const uint32_t subaccount = utxos.at(taker_asset_id).at(0).at("subaccount");

        if (m_receive_address.empty()) {
            // Fetch a new address to receive the swapped asset on
            const nlohmann::json addr_details = { { "subaccount", subaccount } };
            add_next_handler(new get_receive_address_call(m_session_parent, addr_details));
            return state_type::make_call;
        }
        if (m_create_details.empty()) {
            // Get the input UTXOs
            auto maker_input = liquidex_get_maker_input(*m_tx, proposal_input);
            nlohmann::json::array_t tx_inputs = { std::move(maker_input) };
            std::set<std::string> asset_ids{ maker_asset_id, taker_asset_id, m_net_params.get_policy_asset() };
            for (const auto& asset_id : asset_ids) {
                add_asset_utxos(utxos, asset_id, tx_inputs);
            }

            auto maker_addressee = liquidex_get_maker_addressee(m_net_params, *m_tx, proposal_output);
            nlohmann::json taker_addressee = std::move(m_receive_address);
            m_receive_address["used"] = true; // Make sure m_receive_address.empty() isn't true
            taker_addressee["asset_id"] = maker_asset_id; // Taker is receiving the makers asset
            taker_addressee["satoshi"] = j_amountref(proposal_input).value();
            nlohmann::json::array_t addressees = { std::move(maker_addressee), std::move(taker_addressee) };

            nlohmann::json create_details
                = { { "addressees", std::move(addressees) }, { "transaction_version", m_tx->get_version() },
                      { "transaction_locktime", m_tx->get_locktime() }, { "utxo_strategy", "manual" },
                      { "utxos", nlohmann::json::object() }, { "transaction_inputs", std::move(tx_inputs) },
                      { "randomize_inputs", false }, { "scalars", proposal.at("scalars") } };
            add_next_handler(new create_transaction_call(m_session_parent, create_details));
            return state_type::make_call;
        }
        if (j_str_is_empty(m_create_details, "error") && !j_bool_or_false(m_create_details, "is_blinded")) {
            // Call blind_transaction to blind the callers side
            add_next_handler(new blind_transaction_call(m_session_parent, std::move(m_create_details)));
            return state_type::make_call;
        }
        return state_type::done;
    }

    void complete_swap_transaction_call::on_next_handler_complete(auth_handler* next_handler)
    {
        if (m_receive_address.empty()) {
            // Call result is our new receive address
            m_receive_address = std::move(next_handler->move_result());
        } else if (m_create_details.empty()) {
            // Call result is our created/blinded tx
            m_create_details = std::move(next_handler->move_result());
            m_result = m_create_details;
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "Unknown next handler called");
        }
    }

    //
    // Validate
    //
    bool validate_call::is_liquidex() const { return m_details.contains(LIQUIDEX_STR); }
    void validate_call::liquidex_impl()
    {
        const auto& proposal = m_details.at(LIQUIDEX_STR).at("proposal");
        liquidex_validate_proposal(proposal);
    }

} // namespace green
