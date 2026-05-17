use anyhow::{Context, Result};
use rocoon_config::RuntimeConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientContractStatus {
    Active,
    CloseRequested,
    Closed,
}

impl ClientContractStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::CloseRequested => "close_requested",
            Self::Closed => "closed",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "close_requested" => Some(Self::CloseRequested),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct CliState {
    owner_address: String,
    cocoon_wallet_address: String,
    proxy_addr: String,
    pub client_contract_address: String,
    pub client_contract_status: ClientContractStatus,
}

impl CliState {
    #[must_use]
    pub fn new(
        config: &RuntimeConfig,
        client_contract_address: &str,
        client_contract_status: ClientContractStatus,
    ) -> Self {
        Self {
            owner_address: config.owner_address.clone(),
            cocoon_wallet_address: config.cocoon_wallet_address.clone(),
            proxy_addr: config.proxy_addr.clone(),
            client_contract_address: client_contract_address.to_string(),
            client_contract_status,
        }
    }

    #[must_use]
    pub fn matches_config(&self, config: &RuntimeConfig) -> bool {
        self.owner_address == config.owner_address
            && self.cocoon_wallet_address == config.cocoon_wallet_address
            && self.proxy_addr == config.proxy_addr
    }

    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "version=1\nowner_address={}\ncocoon_wallet_address={}\nproxy_addr={}\nclient_contract_address={}\nclient_contract_status={}\n",
            self.owner_address,
            self.cocoon_wallet_address,
            self.proxy_addr,
            self.client_contract_address,
            self.client_contract_status.as_str()
        )
    }

    /// # Errors
    ///
    /// Returns an error when the state version is unsupported or a required
    /// state field is missing.
    pub fn parse(data: &str) -> Result<Self> {
        let mut version = None;
        let mut owner_address = None;
        let mut cocoon_wallet_address = None;
        let mut proxy_addr = None;
        let mut client_contract_address = None;
        let mut client_contract_status = None;

        for line in data.lines().map(str::trim) {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "version" => version = Some(value.to_string()),
                "owner_address" => owner_address = Some(value.to_string()),
                "cocoon_wallet_address" => cocoon_wallet_address = Some(value.to_string()),
                "proxy_addr" => proxy_addr = Some(value.to_string()),
                "client_contract_address" => client_contract_address = Some(value.to_string()),
                "client_contract_status" => {
                    client_contract_status = ClientContractStatus::parse(value);
                }
                _ => {}
            }
        }

        if version.as_deref() != Some("1") {
            anyhow::bail!("unsupported rocoon state version");
        }

        Ok(Self {
            owner_address: required_state_field(owner_address, "owner_address")?,
            cocoon_wallet_address: required_state_field(
                cocoon_wallet_address,
                "cocoon_wallet_address",
            )?,
            proxy_addr: required_state_field(proxy_addr, "proxy_addr")?,
            client_contract_address: required_state_field(
                client_contract_address,
                "client_contract_address",
            )?,
            client_contract_status: client_contract_status.unwrap_or(ClientContractStatus::Active),
        })
    }
}

fn required_state_field(value: Option<String>, name: &str) -> anyhow::Result<String> {
    value.with_context(|| format!("missing {name} in rocoon state"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_state_parse_defaults_old_cache_to_active() -> Result<()> {
        let state = CliState::parse(
            "version=1\nowner_address=owner\ncocoon_wallet_address=wallet\nproxy_addr=proxy\nclient_contract_address=contract\n",
        )?;

        assert_eq!(state.client_contract_status, ClientContractStatus::Active);
        Ok(())
    }

    #[test]
    fn cli_state_round_trips_client_contract_status() -> Result<()> {
        let state = CliState::parse(
            "version=1\nowner_address=owner\ncocoon_wallet_address=wallet\nproxy_addr=proxy\nclient_contract_address=contract\nclient_contract_status=closed\n",
        )?;

        assert_eq!(state.client_contract_status, ClientContractStatus::Closed);
        assert!(state.render().contains("client_contract_status=closed\n"));
        Ok(())
    }
}
