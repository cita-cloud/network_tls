mod codec;
mod config;
mod peer;
mod proto;
mod server;

use std::path::PathBuf;

use clap::App;
use clap::Arg;

use tracing::Level;

use crate::config::load_config;
use crate::server::Server;

fn main() {
    let run_cmd = App::new("run")
        .alias("r")
        .about("run network service")
        .arg(
            Arg::new("config")
                .about("the network config")
                .takes_value(true)
                .validator(|s| s.parse::<PathBuf>())
                .default_value("config.toml"),
        )
        .arg(
            Arg::new("stdout")
                .about("if specified, log to stdout")
                .long("stdout")
                .conflicts_with_all(&["log-dir", "log-file-name"]),
        )
        .arg(
            Arg::new("log-dir")
                .about("the log dir")
                .short('d')
                .long("log-dir")
                .takes_value(true)
                .validator(|s| s.parse::<PathBuf>()),
        )
        .arg(
            Arg::new("log-file-name")
                .about("the log file name")
                .short('f')
                .long("log-file-name")
                .takes_value(true)
                .validator(|s| s.parse::<PathBuf>()),
        );

    let gen_config_cmd = App::new("gen-config")
        .alias("g")
        .about("generate TEST-ONLY network config")
        .arg(
            Arg::new("peer-count")
                .about("how many peers to generate")
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

            let log_dir = m.value_of("log-dir");
            let log_file_name = m.value_of("log-file-name");
            let (writer, _guard) = if m.is_present("stdout") {
                tracing_appender::non_blocking(std::io::stdout())
            } else {
                let log_dir = log_dir.unwrap_or("logs");
                let log_file_name = log_file_name.unwrap_or("network-service.log");
                let file_appender = tracing_appender::rolling::daily(log_dir, log_file_name);
                tracing_appender::non_blocking(file_appender)
            };

            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_ansi(false)
                .with_writer(writer)
                .init();

            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(Server::setup(config));
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
