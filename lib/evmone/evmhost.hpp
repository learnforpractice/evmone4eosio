#include <evmc/evmc.hpp>
#include <eth_account.hpp>
#include "utility.hpp"

using namespace evmc;
using namespace std;

constexpr auto max_gas_limit = std::numeric_limits<int64_t>::max();

class EVMHost : public evmc::Host {
    evmc_tx_context tx_context{};
    evmc_revision version = EVMC_BYZANTIUM;

protected:
    vector<evm_log> logs;
public:
    explicit EVMHost(const evmc_tx_context& ctx, evmc_revision _version) noexcept;
    explicit EVMHost(const evmc_address& _origin, evmc_revision _version) noexcept;
    virtual void append_logs(vector<evm_log>& _logs);
    virtual vector<evm_log>& get_logs();
    virtual bool account_exists(const address& addr) const override;
    virtual bytes32 get_storage(const address& addr, const bytes32& key) const override;
    virtual evmc_storage_status set_storage(const address& addr,
                                            const bytes32& key,
                                            const bytes32& value) override;
    virtual uint256be get_balance(const address& addr) const override;
    virtual size_t get_code_size(const address& addr) const override;
    virtual bytes32 get_code_hash(const address& addr) const override;
    virtual size_t copy_code(const address& addr,
                             size_t code_offset,
                             uint8_t* buffer_data,
                             size_t buffer_size) const override;
    virtual void selfdestruct(const address& addr, const address& beneficiary) override;
    virtual result call(const evmc_message& msg) override;
    virtual evmc_tx_context get_tx_context() const override;
    virtual bytes32 get_block_hash(int64_t block_number) const override;

    /// @copydoc evmc_host_interface::emit_log
    virtual void emit_log(const address& addr,
                          const uint8_t* data,
                          size_t data_size,
                          const bytes32 topics[],
                          size_t num_topics) override;
};

