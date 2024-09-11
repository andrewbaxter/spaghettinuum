use {
    htwrap::{
        htreq::{
            self,
            Conn,
        },
        UriJoin,
    },
    loga::{
        ea,
        Log,
        ResultContext,
    },
    serde::de::DeserializeOwned,
    spaghettinuum::{
        interface::{
            config::ENV_API_ADMIN_TOKEN,
            stored::identity::Identity,
            wire::api::admin::v1::{
                AdminAllowIdentityBody,
                AdminIdentity,
            },
        },
        publishing::system_publisher_url_pairs,
        resolving::{
            connect_publisher_node,
            default_resolver_url_pairs,
            UrlPair,
        },
        ta_res,
    },
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        env,
    },
};

pub mod args {
    use {
        aargvark::{
            traits_impls::AargvarkJson,
            Aargvark,
        },
        spaghettinuum::interface::stored,
        std::{
            collections::{
                HashMap,
                HashSet,
            },
            path::PathBuf,
        },
    };

    #[derive(Aargvark)]
    pub struct NewLocalIdentity {
        /// Store the new id and secret in a file at this path
        pub path: PathBuf,
    }

    #[derive(Aargvark)]
    pub struct AllowIdentity {
        pub identity_id: String,
        /// Associate the identity with a tag for easier management
        pub group: Option<String>,
    }

    #[derive(Aargvark)]
    pub struct DisallowIdentity {
        pub identity_id: String,
    }

    #[derive(Aargvark)]
    pub struct ListKeys {
        pub identity: String,
    }

    #[derive(Aargvark)]
    #[vark(break_help)]
    pub enum Admin {
        /// Get detailed node health information
        HealthDetail,
        /// List identities allowed to publish
        ListAllowedIdentities,
        /// Register an identity with the publisher, allowing it to publish
        AllowIdentity(AllowIdentity),
        /// Unregister an identity with the publisher, disallowing it from publishing
        DisallowIdentity(DisallowIdentity),
        /// List announced identities
        ListAnnouncements,
        /// List keys published here for an identity
        ListKeys(ListKeys),
        /// Register and unregister identities.
        ///
        /// The JSON is an object with groups as keys, and lists of identity ids as values.
        ///
        /// Any groups not in the JSON won't be synced - deleting a group won't remove all
        /// entries in the group.  In order to clear a group, you must specify an empty
        /// list for that group in the JSON.
        SyncAllowedIdentities(AargvarkJson<HashMap<String, HashSet<stored::identity::Identity>>>),
    }
}

fn admin_headers() -> Result<HashMap<String, String>, loga::Error> {
    let mut out = HashMap::new();
    let env_key = ENV_API_ADMIN_TOKEN;
    out.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            env::var(
                env_key,
            ).context_with(
                "This operation uses an admin endpoint, but missing the admin token in the environment",
                ea!(key = env_key),
            )?
        ),
    );
    return Ok(out);
}

async fn api_list<
    T: DeserializeOwned,
>(
    log: &Log,
    conn: &mut Conn,
    base_url: &UrlPair,
    path: &str,
    get_key: fn(&T) -> String,
) -> Result<Vec<T>, loga::Error> {
    let mut out = vec![];
    let admin_headers = admin_headers()?;
    let mut res = htreq::get(log, conn, &base_url.url.join(path), &admin_headers, 1024 * 1024).await?;
    loop {
        let page: Vec<T> =
            serde_json::from_slice(&res).context("Failed to parse response page from publisher admin")?;
        let after = match page.last() {
            Some(a) => Some(get_key(a)),
            None => None,
        };
        out.extend(page);
        let Some(after) = after else {
            break;
        };
        res =
            htreq::get(
                log,
                conn,
                &base_url.url.join(format!("{}?after={}", path, after)),
                &admin_headers,
                1024 * 1024,
            ).await?;
    }
    return Ok(out);
}

pub async fn run(log: &Log, config: args::Admin) -> Result<(), loga::Error> {
    let resolvers = default_resolver_url_pairs(log)?;
    let publishers = system_publisher_url_pairs(log)?;
    match config {
        args::Admin::HealthDetail => {
            for pair in publishers {
                let pair = pair.join("admin/health");
                log.log_with(loga::DEBUG, "Sending health detail request (GET)", ea!(url = pair));
                htreq::get(
                    log,
                    &mut connect_publisher_node(log, &resolvers, &pair).await?,
                    &pair.url,
                    &admin_headers()?,
                    10 * 1024,
                ).await?;
            }
        },
        args::Admin::AllowIdentity(config) => {
            for pair in publishers {
                let pair = pair.join(format!("publish/admin/allowed_identities/{}", config.identity_id));
                log.log_with(loga::DEBUG, "Sending register request (POST)", ea!(url = pair));
                htreq::post_json::<()>(
                    log,
                    &mut connect_publisher_node(log, &resolvers, &pair).await?,
                    &pair.url,
                    &admin_headers()?,
                    AdminAllowIdentityBody { group: config.group.clone().unwrap_or_default() },
                    100,
                ).await?;
            }
        },
        args::Admin::DisallowIdentity(config) => {
            for pair in publishers {
                let pair = pair.join(format!("publish/admin/allowed_identities/{}", config.identity_id));
                log.log_with(loga::DEBUG, "Sending unregister request (POST)", ea!(url = pair));
                htreq::delete(
                    log,
                    &mut connect_publisher_node(log, &resolvers, &pair).await?,
                    &pair.url,
                    &admin_headers()?,
                    100,
                ).await?;
            }
        },
        args::Admin::ListAllowedIdentities => {
            let mut errs = vec![];
            for pair in publishers {
                match async {
                    ta_res!(());
                    let out =
                        api_list::<AdminIdentity>(
                            log,
                            &mut connect_publisher_node(log, &resolvers, &pair)
                                .await
                                .context("Error connecting to server")?,
                            &pair,
                            "publish/admin/allowed_identities",
                            |v| v.identity.to_string(),
                        )
                            .await
                            .stack_context(log, "Error listing allowed identities")?;
                    println!("{}", serde_json::to_string_pretty(&out).unwrap());
                    return Ok(());
                }.await {
                    Ok(_) => {
                        return Ok(());
                    },
                    Err(e) => {
                        errs.push(e.context_with("Error reaching publisher", ea!(url = pair)));
                    },
                }
            }
            return Err(loga::agg_err("Error making request", errs));
        },
        args::Admin::ListAnnouncements => {
            let mut errs = vec![];
            for pair in publishers {
                match async {
                    ta_res!(());
                    let out =
                        api_list::<Identity>(
                            log,
                            &mut connect_publisher_node(log, &resolvers, &pair)
                                .await
                                .context("Error connecting to server")?,
                            &pair,
                            "publish/admin/announcements",
                            |v| v.to_string(),
                        )
                            .await
                            .stack_context(log, "Error listing publishing identities")?;
                    println!("{}", serde_json::to_string_pretty(&out).unwrap());
                    return Ok(());
                }.await {
                    Ok(_) => {
                        return Ok(());
                    },
                    Err(e) => {
                        errs.push(e.context_with("Error reaching publisher", ea!(url = pair)));
                    },
                }
            }
            return Err(loga::agg_err("Error making request", errs));
        },
        args::Admin::ListKeys(config) => {
            let mut errs = vec![];
            for pair in publishers {
                let pair = pair.join(format!("publish/admin/keys/{}", config.identity));
                match async {
                    ta_res!(());
                    println!(
                        "{}",
                        htreq::get_text(
                            log,
                            &mut connect_publisher_node(log, &resolvers, &pair).await?,
                            &pair.url,
                            &admin_headers()?,
                            1024 * 1024,
                        ).await?
                    );
                    return Ok(());
                }.await {
                    Ok(_) => {
                        return Ok(());
                    },
                    Err(e) => {
                        errs.push(e.context_with("Error reaching publisher", ea!(url = pair)));
                    },
                }
            }
            return Err(loga::agg_err("Error making request", errs));
        },
        args::Admin::SyncAllowedIdentities(sync) => {
            for pair in publishers {
                let mut conn =
                    connect_publisher_node(log, &resolvers, &pair).await.context("Error connecting to server")?;
                let identities =
                    api_list::<AdminIdentity>(
                        log,
                        &mut conn,
                        &pair,
                        "publish/admin/allowed_identities",
                        |v| v.identity.to_string(),
                    )
                        .await
                        .stack_context(log, "Error listing allowed identities")?;
                let mut have = HashMap::<String, HashSet<Identity>>::new();
                for entry in identities {
                    let group = have.entry(entry.group).or_default();
                    group.insert(entry.identity);
                }
                for (group, want) in &sync.value {
                    let mut have = have.remove(group).unwrap_or_default();
                    for identity_id in want {
                        if have.remove(&identity_id) {
                            continue;
                        }
                        htreq::post(
                            log,
                            &mut conn,
                            &pair.url.join(format!("publish/admin/allowed_identities/{}", identity_id)),
                            &admin_headers()?,
                            vec![],
                            100,
                        ).await?;
                    }
                    for identity_id in have {
                        htreq::delete(
                            log,
                            &mut conn,
                            &pair.url.join(format!("publish/admin/allowed_identities/{}", identity_id)),
                            &admin_headers()?,
                            100,
                        ).await?;
                    }
                }
            }
            return Ok(());
        },
    }
    return Ok(());
}
