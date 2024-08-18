use {
    htwrap::htreq,
    itertools::Itertools,
    loga::{
        ea,
        Log,
        ResultContext,
    },
    spaghettinuum::{
        resolving::{
            connect_resolver_node,
            system_resolver_url_pairs,
        },
        service::resolver::API_ROUTE_RESOLVE,
        ta_res,
    },
    std::collections::HashMap,
};

pub mod args {
    use {
        aargvark::Aargvark,
    };

    #[derive(Aargvark)]
    pub struct Query {
        /// Identity to query
        pub identity: String,
        /// Keys published by the identity, to query
        pub keys: Vec<String>,
    }
}

pub async fn run_get(log: &Log, config: args::Query) -> Result<(), loga::Error> {
    let mut errs = vec![];
    for pair in system_resolver_url_pairs(log)? {
        match async {
            ta_res!(());
            let pair =
                pair.join(
                    format!(
                        "{}/v1/{}?{}",
                        API_ROUTE_RESOLVE,
                        config.identity,
                        config.keys.iter().map(|k| urlencoding::encode(k)).join(",")
                    ),
                );
            log.log_with(loga::DEBUG, "Sending query request", ea!(url = pair));
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::from_slice::<serde_json::Value>(
                        &htreq::get(
                            log,
                            &mut connect_resolver_node(&pair).await?,
                            &pair.url,
                            &HashMap::new(),
                            1024 * 1024,
                        ).await?,
                    ).stack_context(log, "Response could not be parsed as JSON")?,
                ).unwrap()
            );
            return Ok(());
        }.await {
            Ok(_) => {
                return Ok(());
            },
            Err(e) => {
                errs.push(e.context_with("Error reaching resolver", ea!(resolver = pair)));
            },
        }
    }
    return Err(loga::agg_err("Error making requests to any resolver", errs));
}
