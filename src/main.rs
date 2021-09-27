mod codec;
mod config;
mod peer;
mod proto;
mod server;

use std::path::PathBuf;

use clap::App;
use clap::Arg;

use crate::config::load_config;
use crate::server::Server;

fn main() {
    let run_cmd = App::new("run").alias("r").about("run network service").arg(
        Arg::new("config")
            .takes_value(true)
            .validator(|s| s.parse::<PathBuf>())
            .default_value("config.toml"),
    );

    let gen_config_cmd = App::new("gen-config")
        .alias("g")
        .about("generate TEST-ONLY network config")
        .arg(
            Arg::new("peer-count")
                .takes_value(true)
                .validator(|s| s.parse::<usize>())
                .default_value("2"),
        );

    let app = App::new("network")
        .about("Network service for CITA-Cloud")
        .subcommands([run_cmd, gen_config_cmd]);

    let matches = app.get_matches();

    match matches.subcommand() {
        Some(("run", m)) => {
            let config = {
                let path = m.value_of("config").unwrap();
                load_config(path)
            };
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move { Server::new(config).serve().await });
        }
        Some(("gen-config", m)) => {
            let peer_count = m.value_of("peer-count").unwrap().parse::<usize>().unwrap();
            config::generate_config(peer_count);
            println!("Done.\nWARNING: This config is for TEST-ONLY.");
        }
        _ => {
            println!("no command provided");
        }
    }
}
