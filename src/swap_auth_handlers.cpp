#include "swap_auth_handlers.hpp"
#include "ga_auth_handlers.hpp"

#include "assertion.hpp"
#include "boost_wrapper.hpp"
#include "containers.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "ga_wally.hpp"
#include "logging.hpp"
#include "session.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

namespace ga {
namespace sdk {
    namespace {
        static nlohmann::json get_tx_input_fields(const wally_tx_ptr& tx, size_t index)
        {
            GDK_RUNTIME_ASSERT(index < tx->num_inputs);
            const wally_tx_input* in = tx->inputs + index;
            nlohmann::json::array_t witness;
            for (size_t i = 0; i < in->witness->num_items; ++i) {
                const auto* item = in->witness->items + i;
                witness.push_back(item->witness_len ? b2h(gsl::make_span(item->witness, item->witness_len)) : "");
            }
            return { { "txhash", b2h_rev(gsl::make_span(in->txhash, sizeof(in->txhash))) }, { "pt_idx", in->index },
                { "sequence", in->sequence }, { "script_sig", b2h(gsl::make_span(in->script, in->script_len)) },
                { "witness", std::move(witness) } };
        }

        static void add_asset_utxos(
            const nlohmann::json& utxos, const std::string& asset_id, nlohmann::json::array_t& used_utxos)
        {
            const auto p = utxos.find(asset_id);
            if (p != utxos.end()) {
                for (const auto& u : *p) {
                    used_utxos.push_back(u);
                }
            }
        }

        static auto liquidex_get_fields(nlohmann::json& in_out)
        {
            nlohmann::json::array_t res;
            res.resize(in_out.size());
            for (size_t i = 0; i < in_out.size(); ++i) {
                res[i]["asset"] = std::move(in_out[i]["asset_id"]);
                res[i]["asset_blinder"] = std::move(in_out[i]["assetblinder"]);
                res[i]["satoshi"] = std::move(in_out[i]["satoshi"]);
                const auto asset = h2b_rev(res[i]["asset"]);
                const uint64_t satoshi = res[i]["satoshi"];
                const auto abf = h2b_rev(res[i]["asset_blinder"]);
                const auto vbf = h2b_rev(in_out[i]["amountblinder"]);
                const auto generator = asset_generator_from_bytes(asset, abf);
                const auto commitment = asset_value_commitment(satoshi, vbf, generator);
                const auto nonce_hash = get_random_bytes<32>();
                res[i]["value_blind_proof"] = b2h(explicit_rangeproof(satoshi, nonce_hash, vbf, commitment, generator));
                // This must be aggregated and removed
                res[i]["scalar"] = b2h(asset_scalar_offset(satoshi, abf, vbf));
            }
            return res;
        }

        static nlohmann::json::array_t liquidex_aggregate_scalars(
            nlohmann::json::array_t& inputs, nlohmann::json::array_t& outputs)
        {
            GDK_RUNTIME_ASSERT(inputs.size() == 1 && outputs.size() == 1);
            const auto input_scalar = h2b(std::move(inputs[0]["scalar"]));
            const auto output_scalar = h2b(std::move(outputs[0]["scalar"]));
            outputs[0].erase("scalar");
            inputs[0].erase("scalar");
            return { b2h(ec_scalar_subtract(input_scalar, output_scalar)) };
        }

        static nlohmann::json liquidex_get_maker_input(const wally_tx_ptr& tx, const nlohmann::json& proposal_input)
        {
            auto maker_input = get_tx_input_fields(tx, 0);
            maker_input["asset_id"] = proposal_input.at("asset");
            maker_input["assetblinder"] = proposal_input.at("asset_blinder");
            maker_input["satoshi"] = proposal_input.at("amount");
            maker_input["amountblinder"] = proposal_input.at("amount_blinder");
            maker_input["skip_signing"] = true;
            return maker_input;
        }

        static nlohmann::json liquidex_get_maker_addressee(
            const network_parameters& net_params, const wally_tx_ptr& tx, const nlohmann::json& proposal_output)
        {
            GDK_RUNTIME_ASSERT(tx->num_outputs);
            const auto& tx_output = tx->outputs[0];
            const auto rangeproof = gsl::make_span(tx_output.rangeproof, tx_output.rangeproof_len);
            const auto nonce = gsl::make_span(tx_output.nonce, tx_output.nonce_len);
            const auto scriptpubkey = gsl::make_span(tx_output.script, tx_output.script_len);

            nlohmann::json ret = { { "address", get_address_from_scriptpubkey(net_params, scriptpubkey) },
                { "is_blinded", true }, { "index", 0 }, { "nonce_commitment", b2h(nonce) },
                { "range_proof", b2h(rangeproof) }, { "asset_id", proposal_output.at("asset") },
                { "assetblinder", proposal_output.at("asset_blinder") }, { "satoshi", proposal_output.at("amount") },
                { "amountblinder", proposal_output.at("amount_blinder") } };
            if (proposal_output.contains("blinding_nonce")) {
                ret["blinding_nonce"] = proposal_output["blinding_nonce"];
            }
            return ret;
        }

        static wally_tx_ptr liquidex_validate_proposal(const nlohmann::json& proposal)
        {
            constexpr bool is_liquid = true;
            GDK_RUNTIME_ASSERT_MSG(proposal.at("version") == 1, "unknown version");
            GDK_RUNTIME_ASSERT_MSG(proposal.dump().length() < 20000, "proposal exceeds maximum length");
            const auto& proposal_input = get_sized_array(proposal, "inputs", 1).at(0);
            const auto& proposal_output = get_sized_array(proposal, "outputs", 1).at(0);
            const auto scalar = h2b(get_sized_array(proposal, "scalars", 1).at(0));
            GDK_RUNTIME_ASSERT_MSG(ec_scalar_verify(scalar), "invalid scalar");
            GDK_RUNTIME_ASSERT_MSG(
                proposal_input.at("asset") != proposal_output.at("asset"), "cannot swap the same asset");
            wally_tx_ptr tx = tx_from_hex(proposal.at("transaction"), tx_flags(is_liquid));
            GDK_RUNTIME_ASSERT_MSG(
                tx->num_inputs == 1 && tx->num_outputs == 1, "unexpected number of inputs or outputs");

            // Verify unblinded values match the transaction commitments
            // TODO: obtain the previous output and verify the input commitments
            const auto output_asset = h2b_rev(proposal_output.at("asset"));
            const auto output_abf = h2b_rev(proposal_output.at("asset_blinder"));
            const auto output_value = proposal_output.at("satoshi");
            const auto value_blind_proof = h2b(proposal_output.at("value_blind_proof"));
            const auto output_asset_commitment = asset_generator_from_bytes(output_asset, output_abf);
            const auto& tx_output = tx->outputs[0];
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
        , m_swap_type(json_get_value(m_details, "swap_type"))
        , m_is_signed(false)
    {
    }

    auth_handler::state_type create_swap_transaction_call::call_impl()
    {
        if (m_swap_type == "liquidex") {
            GDK_RUNTIME_ASSERT_MSG(json_get_value(m_details, "input_type") == "liquidex_v1", "unknown input_type");
            GDK_RUNTIME_ASSERT_MSG(json_get_value(m_details, "output_type") == "liquidex_v1", "unknown output_type");
            return liquidex_impl();
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "unknown swap_type");
        }
        return state_type::error; // Unreachable
    }

    auth_handler::state_type create_swap_transaction_call::liquidex_impl()
    {
        const auto& liquidex_details = m_details.at("liquidex_v1");
        const auto& send = get_sized_array(liquidex_details, "send", 1).at(0);
        const auto& receive = get_sized_array(liquidex_details, "receive", 1).at(0);
        // TODO: We may wish to allow receiving to a different subaccount.
        //       For now, receive to the same subaccount we are sending from
        const uint32_t subaccount = send.at("subaccount");

        if (m_receive_address.empty()) {
            // Fetch a new address to receive the swapped asset on
            // TODO: Further validate the inputs
            const nlohmann::json addr_details = { { "subaccount", subaccount } };
            add_next_handler(new get_receive_address_call(m_session_parent, addr_details));
            return state_type::make_call;
        }
        if (m_create_details.empty()) {
            // Call create_transaction to create the swap tx
            nlohmann::json addressee = { { "address", m_receive_address.at("address") } };
            addressee.update(receive);
            std::vector<nlohmann::json> addressees{ std::move(addressee) };
            std::vector<nlohmann::json> used_utxos{ send };
            nlohmann::json utxos{ { send.at("asset_id"), used_utxos } };
            nlohmann::json create_details = { { "addressees", std::move(addressees) }, { "is_partial", true },
                { "utxo_strategy", "manual" }, { "utxos", utxos }, { "used_utxos", std::move(used_utxos) } };
            add_next_handler(new create_transaction_call(m_session_parent, create_details));
            return state_type::make_call;
        }
        if (!json_get_value(m_create_details, "error").empty()) {
            m_result = std::move(m_create_details);
            return state_type::done; // Create transaction returned an error, do not attempt to sign
        }
        // Call sign_transaction to sign the callers side
        constexpr uint32_t sighash = WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY;
        m_create_details.at("used_utxos").at(0)["user_sighash"] = sighash;
        nlohmann::json::array_t sign_with = { "user" };
        if (!tx_has_amp_inputs(*m_session_parent.get_nonnull_impl(), m_create_details)) {
            sign_with.emplace_back("green-backend");
        }
        m_create_details["sign_with"] = std::move(sign_with);
        add_next_handler(new sign_transaction_call(m_session_parent, m_create_details));
        return state_type::done; // We are complete once tx signing is done
    }

    void create_swap_transaction_call::on_next_handler_complete(auth_handler* next_handler)
    {
        if (m_receive_address.empty()) {
            // Call result is our new receive address
            m_receive_address = std::move(next_handler->move_result());
        } else if (m_create_details.empty()) {
            // Call result is our created tx
            m_create_details = std::move(next_handler->move_result());
        } else if (!m_is_signed) {
            // Call result is our signed tx
            auto result = std::move(next_handler->move_result());
            // Create liquidex_v1 proposal to return
            auto& tx_inputs = result.at("used_utxos");
            auto& tx_outputs = result.at("transaction_outputs");
            nlohmann::json::array_t inputs = liquidex_get_fields(tx_inputs);
            nlohmann::json::array_t outputs = liquidex_get_fields(tx_outputs);
            nlohmann::json::array_t scalars = liquidex_aggregate_scalars(inputs, outputs);
            GDK_RUNTIME_ASSERT(!inputs[0].contains("scalar") && !outputs[0].contains("scalar"));
            auto proposal = nlohmann::json({ { "version", 1 }, { "transaction", std::move(result["transaction"]) },
                { "inputs", std::move(inputs) }, { "outputs", std::move(outputs) },
                { "scalars", std::move(scalars) } });
            if (tx_has_amp_inputs(*m_session_parent.get_nonnull_impl(), m_create_details)) {
                proposal["inputs"][0]["script"] = std::move(tx_inputs.at(0).at("prevout_script"));
                proposal["outputs"][0]["blinding_nonce"] = std::move(tx_outputs.at(0).at("blinding_nonce"));
            }
            m_result["liquidex_v1"] = nlohmann::json::object();
            m_result["liquidex_v1"]["proposal"] = std::move(proposal);
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
        , m_swap_type(json_get_value(m_details, "swap_type"))
    {
    }

    auth_handler::state_type complete_swap_transaction_call::call_impl()
    {
        if (m_swap_type == "liquidex") {
            GDK_RUNTIME_ASSERT_MSG(json_get_value(m_details, "input_type") == "liquidex_v0", "unknown input_type");
            GDK_RUNTIME_ASSERT_MSG(json_get_value(m_details, "output_type") == "transaction", "unknown output_type");
            GDK_RUNTIME_ASSERT(m_net_params.is_liquid());
            return liquidex_impl();
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "unknown swap_type");
        }
        return state_type::error; // Unreachable
    }

    auth_handler::state_type complete_swap_transaction_call::liquidex_impl()
    {
        // TODO: allow to take multiple proposal at once
        const auto& proposal = get_sized_array(m_details.at("liquidex_v0"), "proposals", 1).at(0);
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
        } else if (m_create_details.empty()) {
            // Get the input UTXOs
            auto maker_input = liquidex_get_maker_input(m_tx, proposal_input);
            nlohmann::json::array_t used_utxos = { std::move(maker_input) };
            std::set<std::string> asset_ids{ maker_asset_id, taker_asset_id, m_net_params.policy_asset() };
            for (const auto& asset_id : asset_ids) {
                add_asset_utxos(utxos, asset_id, used_utxos);
            }

            auto maker_addressee = liquidex_get_maker_addressee(m_net_params, m_tx, proposal_output);
            nlohmann::json taker_addressee = { { "address", m_receive_address.at("address") },
                { "asset_id", maker_asset_id }, // Taker is receiving the makers asset
                { "satoshi", proposal_input.at("amount") } };
            nlohmann::json::array_t addressees = { std::move(maker_addressee), std::move(taker_addressee) };

            nlohmann::json create_details = { { "addressees", std::move(addressees) },
                { "transaction_version", m_tx->version }, { "transaction_locktime", m_tx->locktime },
                { "utxo_strategy", "manual" }, { "utxos", nlohmann::json::object() },
                { "used_utxos", std::move(used_utxos) }, { "randomize_inputs", false } };
            add_next_handler(new create_transaction_call(m_session_parent, create_details));
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
            // Call result is our created tx
            m_create_details = std::move(next_handler->move_result());
            m_result = m_create_details;
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "Unknown next handler called");
        }
    }

    //
    // Validate
    //
    validate_call::validate_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "validate")
        , m_details(details)
    {
    }

    auth_handler::state_type validate_call::call_impl()
    {
        m_result["errors"] = nlohmann::json::array();
        m_result["is_valid"] = false;
        try {
            liquidex_impl();
            m_result["is_valid"] = true;
        } catch (const std::exception& e) {
            m_result["errors"].emplace_back(e.what());
        }
        return state_type::done;
    }

    void validate_call::liquidex_impl()
    {
        const auto& proposal = m_details.at("liquidex_v1").at("proposal");
        liquidex_validate_proposal(proposal);
    }
} // namespace sdk
} // namespace ga
