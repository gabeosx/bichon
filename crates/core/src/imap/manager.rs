//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::account::entity::{AuthType, Encryption};
use crate::account::migration::{AccountModel, AccountType};
use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::imap::capabilities::{capability_to_string, check_capabilities, fetch_capabilities};
use crate::imap::client::{Client, UidOnlyClient};
use crate::imap::oauth2::OAuth2;
use crate::imap::session::SessionStream;
use crate::oauth2::token::OAuth2AccessToken;
use crate::{bichon_version, decrypt, raise_error};
use async_imap::types::{Capabilities, Capability};
use async_imap::Session;
use bichon_uidonly::{AdapterHandle, AdapterLimits, CommandLimits, UidOnlyAdapter, UidOnlySession};
use std::num::NonZeroU32;
use tracing::{error, warn};

pub struct ImapConnectionManager;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcquisitionConnectionIdentity {
    endpoint: String,
    principal: String,
    encryption: Encryption,
    auth_type: AuthType,
    proxy_id: Option<u64>,
    use_dangerous: bool,
}

pub(crate) fn acquisition_connection_identity(
    account: &AccountModel,
) -> BichonResult<AcquisitionConnectionIdentity> {
    let imap = account.imap.as_ref().ok_or_else(|| {
        raise_error!(
            "IMAP account has no endpoint".into(),
            ErrorCode::MissingConfiguration
        )
    })?;
    Ok(AcquisitionConnectionIdentity {
        endpoint: format!("{}:{}", imap.host.to_ascii_lowercase(), imap.port),
        principal: account
            .login_name
            .clone()
            .unwrap_or_else(|| account.email.clone()),
        encryption: imap.encryption.clone(),
        auth_type: imap.auth.auth_type.clone(),
        proxy_id: imap.use_proxy,
        use_dangerous: account.use_dangerous,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcquisitionRoute {
    Standard,
    UidOnly,
    Limited,
}

fn acquisition_route(
    uidonly_advertised: bool,
    partial_advertised: bool,
    message_limit_advertised: bool,
) -> AcquisitionRoute {
    if uidonly_advertised && partial_advertised {
        AcquisitionRoute::UidOnly
    } else if uidonly_advertised || message_limit_advertised {
        AcquisitionRoute::Limited
    } else {
        AcquisitionRoute::Standard
    }
}

fn capability_matches(capability: &Capability, expected: &str) -> bool {
    capability_to_string(capability).eq_ignore_ascii_case(expected)
}

fn has_capability(capabilities: &Capabilities, expected: &str) -> bool {
    capabilities
        .iter()
        .any(|capability| capability_matches(capability, expected))
}

fn advertised_message_limit(capabilities: &Capabilities) -> Option<NonZeroU32> {
    capabilities
        .iter()
        .filter_map(|capability| {
            let Capability::Atom(value) = capability else {
                return None;
            };
            let (name, value) = value.split_once('=')?;
            if !name.eq_ignore_ascii_case("MESSAGELIMIT") {
                return None;
            }
            value.parse::<u32>().ok().and_then(NonZeroU32::new)
        })
        .min()
}

fn has_message_limit_capability(capabilities: &Capabilities) -> bool {
    capabilities.iter().any(|capability| {
        let Capability::Atom(value) = capability else {
            return false;
        };
        value
            .split_once('=')
            .map(|(name, _)| name)
            .unwrap_or(value)
            .eq_ignore_ascii_case("MESSAGELIMIT")
    })
}

fn conservative_message_limit(
    first: Option<NonZeroU32>,
    second: Option<NonZeroU32>,
) -> Option<NonZeroU32> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(limit), None) | (None, Some(limit)) => Some(limit),
        (None, None) => None,
    }
}

/// An authenticated acquisition connection. Existing callers keep using
/// `build`; only the archive acquisition path opts into UIDONLY.
pub(crate) enum AcquisitionConnection {
    Standard(Session<Box<dyn SessionStream>>),
    UidOnly {
        session: Box<UidOnlySession<Box<dyn SessionStream>>>,
        message_limit: Option<NonZeroU32>,
    },
}

impl ImapConnectionManager {
    async fn create_client(
        account: &AccountModel,
        response_limits: Option<AdapterLimits>,
    ) -> BichonResult<Client> {
        assert_eq!(account.account_type, AccountType::IMAP);
        let imap = account.imap.as_ref().unwrap();
        match response_limits {
            Some(limits) => {
                Client::connection_with_limits(
                    &imap.host,
                    &imap.encryption,
                    imap.port,
                    imap.use_proxy,
                    account.use_dangerous,
                    limits,
                )
                .await
            }
            None => {
                Client::connection(
                    &imap.host,
                    &imap.encryption,
                    imap.port,
                    imap.use_proxy,
                    account.use_dangerous,
                )
                .await
            }
        }
    }

    async fn authenticate(
        client: Client,
        account: &AccountModel,
    ) -> BichonResult<Session<Box<dyn SessionStream>>> {
        assert_eq!(account.account_type, AccountType::IMAP);
        let imap = account.imap.as_ref().unwrap();
        let login_name = account.login_name.clone().unwrap_or(account.email.clone());
        match &imap.auth.auth_type {
            AuthType::Password => {
                let password = &imap.auth.password.clone().ok_or_else(|| {
                    raise_error!(
                        "Imap auth type is Passwd, but password not set".into(),
                        ErrorCode::MissingConfiguration
                    )
                })?;

                let password = decrypt!(&password)?;
                client.login(&login_name, &password).await.map_err(|e| {
                    error!(
                        "IMAP password auth failed for username '{}': {}",
                        login_name, e
                    );
                    e
                })
            }
            AuthType::OAuth2 => {
                let record = OAuth2AccessToken::get(account.id)?;
                let access_token = record.and_then(|r| r.access_token).ok_or_else(|| {
                    raise_error!(
                        "Imap auth type is OAuth2, but OAuth2 authorization is not yet complete."
                            .into(),
                        ErrorCode::MissingConfiguration
                    )
                })?;
                client
                    .authenticate(OAuth2::new(login_name.clone(), access_token))
                    .await
                    .map_err(|e| {
                        error!(
                            "IMAP OAuth2 auth failed for username '{}': {}",
                            login_name, e
                        );
                        e
                    })
            }
        }
    }

    async fn authenticate_uidonly(
        client: UidOnlyClient,
        account: &AccountModel,
    ) -> BichonResult<(
        Session<UidOnlyAdapter<Box<dyn SessionStream>>>,
        AdapterHandle,
    )> {
        assert_eq!(account.account_type, AccountType::IMAP);
        let imap = account
            .imap
            .as_ref()
            .expect("IMAP account has configuration");
        let login_name = account.login_name.clone().unwrap_or(account.email.clone());
        match &imap.auth.auth_type {
            AuthType::Password => {
                let password = imap.auth.password.as_ref().ok_or_else(|| {
                    raise_error!(
                        "Imap auth type is Passwd, but password not set".into(),
                        ErrorCode::MissingConfiguration
                    )
                })?;
                let password = decrypt!(password)?;
                client.login(&login_name, &password).await.inspect_err(|_| {
                    error!("bounded IMAP password authentication failed");
                })
            }
            AuthType::OAuth2 => {
                let record = OAuth2AccessToken::get(account.id)?;
                let access_token =
                    record
                        .and_then(|record| record.access_token)
                        .ok_or_else(|| {
                            raise_error!(
                        "Imap auth type is OAuth2, but OAuth2 authorization is not yet complete."
                            .into(),
                        ErrorCode::MissingConfiguration
                    )
                        })?;
                client
                    .authenticate(OAuth2::new(login_name, access_token))
                    .await
                    .inspect_err(|_| {
                        error!("bounded IMAP OAuth2 authentication failed");
                    })
            }
        }
    }

    pub async fn build(account_id: u64) -> BichonResult<Session<Box<dyn SessionStream>>> {
        Self::build_with_limits(account_id, None).await
    }

    async fn build_with_limits(
        account_id: u64,
        response_limits: Option<AdapterLimits>,
    ) -> BichonResult<Session<Box<dyn SessionStream>>> {
        let account = AccountModel::get(account_id)?;
        Self::build_account_with_limits(&account, response_limits).await
    }

    async fn build_account_with_limits(
        account: &AccountModel,
        response_limits: Option<AdapterLimits>,
    ) -> BichonResult<Session<Box<dyn SessionStream>>> {
        let account_id = account.id;
        let account_email = account.email.clone();

        let mut client = None;
        for attempt in 0..3u32 {
            match Self::create_client(account, response_limits.clone()).await {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(error) if error.code() == ErrorCode::NetworkError && attempt < 2 => {
                    warn!(
                        "IMAP connection attempt {}/3 to {} failed (network error), retrying...",
                        attempt + 1,
                        account_email
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                Err(error) => {
                    error!(
                        "Failed to create IMAP {}'s client: {:#?}",
                        account_email, error
                    );
                    return Err(error);
                }
            }
        }

        let client = client.ok_or_else(|| {
            raise_error!(
                format!(
                    "Failed to create IMAP {}'s client after 3 attempts",
                    account_email
                ),
                ErrorCode::NetworkError
            )
        })?;

        let mut session = match Self::authenticate(client, account).await {
            Ok(session) => session,
            Err(error) => {
                error!("Failed to authenticate IMAP session: {:#?}", error);
                return Err(error);
            }
        };

        match fetch_capabilities(&mut session).await {
            Ok(capabilities) => {
                let to_save: Vec<String> = capabilities.iter().map(capability_to_string).collect();
                AccountModel::update_capabilities(account_id, to_save)?;
                if let Err(error) = check_capabilities(&capabilities) {
                    error!("Failed to check IMAP capabilities: {:#?}", error);
                    return Err(error);
                }

                if capabilities.has_str("ID") || capabilities.has_str("id") {
                    if let Err(e) = session
                        .id([
                            ("name", Some("bichon")),
                            ("version", Some(bichon_version!())),
                            ("vendor", Some("rustmailer")),
                        ])
                        .await
                    {
                        warn!("IMAP ID command failed (ignored): {:#?}", e);
                    }
                }
            }
            Err(error) => {
                error!("Failed to fetch IMAP capabilities: {:#?}", error);
                return Err(error);
            }
        }

        Ok(session)
    }

    /// Builds an acquisition connection and enables RFC 9586 UIDONLY before
    /// any mailbox is selected. Calling this method again after a reconnect
    /// necessarily re-enables UIDONLY because the mode is connection-scoped.
    ///
    /// Servers without UIDONLY return the already-authenticated standard
    /// session, preserving the pre-existing acquisition behavior.
    #[cfg(test)]
    pub(crate) async fn build_acquisition(
        account_id: u64,
        adapter_limits: AdapterLimits,
        command_limits: CommandLimits,
    ) -> BichonResult<AcquisitionConnection> {
        Self::build_acquisition_at_endpoint(account_id, None, adapter_limits, command_limits).await
    }

    /// Build both the probe and activation connections from one immutable
    /// account snapshot. When `expected_endpoint` is present, a concurrent or
    /// persisted endpoint edit fails closed before any credentials are sent to
    /// a different host.
    pub(crate) async fn build_acquisition_at_endpoint(
        account_id: u64,
        expected_identity: Option<&AcquisitionConnectionIdentity>,
        adapter_limits: AdapterLimits,
        command_limits: CommandLimits,
    ) -> BichonResult<AcquisitionConnection> {
        let account = AccountModel::get(account_id)?;
        let imap = account.imap.as_ref().ok_or_else(|| {
            raise_error!(
                "IMAP account has no endpoint".into(),
                ErrorCode::MissingConfiguration
            )
        })?;
        let current_identity = acquisition_connection_identity(&account)?;
        if expected_identity.is_some_and(|expected| expected != &current_identity) {
            return Err(raise_error!(
                "IMAP connection identity changed during UIDONLY acquisition; refusing to reconnect".into(),
                ErrorCode::Incompatible
            ));
        }

        let mut session =
            Self::build_account_with_limits(&account, Some(adapter_limits.clone())).await?;
        let capabilities = fetch_capabilities(&mut session).await?;
        let probed_message_limit = advertised_message_limit(&capabilities);
        let message_limit_advertised = has_message_limit_capability(&capabilities);
        if message_limit_advertised && probed_message_limit.is_none() {
            session.logout().await.ok();
            return Err(raise_error!(
                "server advertises an invalid MESSAGELIMIT; completeness cannot be claimed".into(),
                ErrorCode::Incompatible
            ));
        }

        match acquisition_route(
            has_capability(&capabilities, "UIDONLY"),
            has_capability(&capabilities, "PARTIAL"),
            message_limit_advertised,
        ) {
            AcquisitionRoute::Standard => {
                // The probe uses UIDONLY's bounded response adapter, whose
                // literal ceiling is intentionally one body chunk. Preserve
                // the legacy provider path on a fresh, unwrapped connection,
                // but build it from the same immutable account snapshot so a
                // concurrent config edit cannot redirect credentials.
                session.logout().await.ok();
                return Ok(AcquisitionConnection::Standard(
                    Self::build_account_with_limits(&account, None).await?,
                ));
            }
            AcquisitionRoute::Limited => {
                session.logout().await.ok();
                return Err(raise_error!(
                    "server advertises a limited acquisition surface without both UIDONLY and PARTIAL; completeness cannot be claimed"
                        .into(),
                    ErrorCode::Incompatible
                ));
            }
            AcquisitionRoute::UidOnly => {}
        }

        session.logout().await.ok();

        let client = UidOnlyClient::connection(
            &imap.host,
            &imap.encryption,
            imap.port,
            imap.use_proxy,
            account.use_dangerous,
            adapter_limits,
        )
        .await?;
        let (mut session, handle) = Self::authenticate_uidonly(client, &account).await?;
        let capabilities = session
            .capabilities()
            .await
            .map_err(|error| raise_error!(format!("{error:#?}"), ErrorCode::ImapCommandFailed))?;
        check_capabilities(&capabilities)?;
        if !has_capability(&capabilities, "UIDONLY") || !has_capability(&capabilities, "PARTIAL") {
            return Err(raise_error!(
                "server stopped advertising UIDONLY or PARTIAL on the activation connection".into(),
                ErrorCode::Incompatible
            ));
        }
        let activation_message_limit = advertised_message_limit(&capabilities);
        if has_message_limit_capability(&capabilities) && activation_message_limit.is_none() {
            return Err(raise_error!(
                "server advertises an invalid MESSAGELIMIT on the activation connection".into(),
                ErrorCode::Incompatible
            ));
        }
        let message_limit =
            conservative_message_limit(probed_message_limit, activation_message_limit);
        let session = UidOnlySession::enable(session, handle, command_limits)
            .await
            .map_err(|error| raise_error!(format!("{error:#?}"), ErrorCode::ImapCommandFailed))?;

        Ok(AcquisitionConnection::UidOnly {
            message_limit,
            session: Box::new(session),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::entity::{AuthConfig, ImapConfig};

    #[test]
    fn non_uidonly_capabilities_route_to_legacy_standard_acquisition() {
        assert_eq!(
            acquisition_route(false, false, false),
            AcquisitionRoute::Standard
        );
        assert_eq!(
            acquisition_route(true, true, true),
            AcquisitionRoute::UidOnly
        );
        assert_eq!(
            acquisition_route(true, false, true),
            AcquisitionRoute::Limited
        );
        assert_eq!(
            acquisition_route(false, false, true),
            AcquisitionRoute::Limited
        );
    }

    #[test]
    fn activation_uses_the_most_conservative_message_limit() {
        let smaller = NonZeroU32::new(500).unwrap();
        let larger = NonZeroU32::new(1_000).unwrap();
        assert_eq!(
            conservative_message_limit(Some(larger), Some(smaller)),
            Some(smaller)
        );
        assert_eq!(
            conservative_message_limit(Some(smaller), None),
            Some(smaller)
        );
    }

    #[test]
    fn uidonly_capability_matching_is_case_insensitive() {
        assert!(capability_matches(
            &Capability::Atom("uIdOnLy".into()),
            "UIDONLY"
        ));
        assert!(capability_matches(
            &Capability::Atom("pArTiAl".into()),
            "PARTIAL"
        ));
    }

    #[test]
    fn acquisition_identity_freezes_principal_and_transport_not_secret_rotation() {
        let account = AccountModel {
            id: 42,
            email: "archive@example.invalid".into(),
            login_name: Some("archive-login".into()),
            imap: Some(ImapConfig {
                host: "imap.example.invalid".into(),
                port: 993,
                encryption: Encryption::Ssl,
                auth: AuthConfig {
                    auth_type: AuthType::Password,
                    password: Some("first-secret".into()),
                },
                use_proxy: Some(7),
            }),
            ..Default::default()
        };
        let expected = acquisition_connection_identity(&account).unwrap();

        let mut rotated_secret = account.clone();
        rotated_secret.imap.as_mut().unwrap().auth.password = Some("rotated-secret".into());
        assert_eq!(
            acquisition_connection_identity(&rotated_secret).unwrap(),
            expected,
            "credential rotation on the same connection identity remains allowed"
        );

        let mut changed_principal = account.clone();
        changed_principal.login_name = Some("other-principal".into());
        assert_ne!(
            acquisition_connection_identity(&changed_principal).unwrap(),
            expected
        );

        let mut changed_auth = account.clone();
        changed_auth.imap.as_mut().unwrap().auth.auth_type = AuthType::OAuth2;
        assert_ne!(
            acquisition_connection_identity(&changed_auth).unwrap(),
            expected
        );

        let mut changed_tls_policy = account.clone();
        changed_tls_policy.use_dangerous = true;
        assert_ne!(
            acquisition_connection_identity(&changed_tls_policy).unwrap(),
            expected
        );

        let mut changed_endpoint = account.clone();
        changed_endpoint.imap.as_mut().unwrap().host = "other.example.invalid".into();
        assert_ne!(
            acquisition_connection_identity(&changed_endpoint).unwrap(),
            expected
        );

        let mut changed_proxy = account.clone();
        changed_proxy.imap.as_mut().unwrap().use_proxy = Some(8);
        assert_ne!(
            acquisition_connection_identity(&changed_proxy).unwrap(),
            expected
        );

        let mut changed_encryption = account;
        changed_encryption.imap.as_mut().unwrap().encryption = Encryption::StartTls;
        assert_ne!(
            acquisition_connection_identity(&changed_encryption).unwrap(),
            expected
        );
    }
}
