use {
    http::{
        uri::Authority,
        Uri,
    },
    loga::{
        ea,
        ResultContext,
    },
    spaghettinuum::interface::config::{
        node::api_config::DEFAULT_API_PORT,
        ENV_API_ADDR,
    },
    std::{
        env,
        str::FromStr,
    },
};

pub fn api_urls() -> Result<Vec<Uri>, loga::Error> {
    let mut out = vec![];
    if let Ok(urls) = env::var(ENV_API_ADDR) {
        for url in urls.split(',') {
            let url =
                Uri::from_str(
                    &url,
                ).context_with("Couldn't parse environment variable", ea!(env_var = ENV_API_ADDR, value = url))?;
            if url.scheme_str() == Some("http") && url.port().is_none() {
                let mut u = url.into_parts();
                u.authority =
                    Some(
                        Authority::try_from(
                            format!(
                                "{}:443",
                                u.authority.map(|a| a.to_string()).unwrap_or(String::new())
                            ).as_bytes(),
                        ).unwrap(),
                    );
                out.push(Uri::from_parts(u).unwrap());
            } else {
                out.push(url);
            }
        }
    } else {
        let (conf, _) =
            hickory_resolver
            ::system_conf
            ::read_system_conf().context("Error reading system conf to find configured DNS server to use for API")?;
        for s in conf.name_servers() {
            out.push(Uri::from_str(&format!("https://{}:{}", match s.socket_addr.ip() {
                std::net::IpAddr::V4(i) => i.to_string(),
                std::net::IpAddr::V6(i) => format!("[{}]", i),
            }, DEFAULT_API_PORT)).unwrap());
        }
    }
    return Ok(out);
}
