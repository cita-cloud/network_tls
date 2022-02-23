// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod codec;
mod config;
mod peer;
mod proto;
mod server;

use std::path::PathBuf;

use clap::Arg;
use clap::Command;

use crate::config::load_config;
use crate::server::Server;

fn main() {
    let run_cmd = Command::new("run")
        .alias("r")
        .about("run network service")
        .arg(
            Arg::new("config")
                .help("the network config")
                .takes_value(true)
                .validator(|s| s.parse::<PathBuf>())
                .default_value("config.toml"),
        )
        .arg(
            Arg::new("stdout")
                .help("if specified, log to stdout")
                .long("stdout")
                .conflicts_with_all(&["log-dir", "log-file-name"]),
        )
        .arg(
            Arg::new("log-dir")
                .help("the log dir")
                .short('d')
                .long("log-dir")
                .takes_value(true)
                .validator(|s| s.parse::<PathBuf>()),
        )
        .arg(
            Arg::new("log-file-name")
                .help("the log file name")
                .short('f')
                .long("log-file-name")
                .takes_value(true)
                .validator(|s| s.parse::<PathBuf>()),
        )
        .arg(
            Arg::new("log-level")
                .help("the log level")
                .short('l')
                .long("log-level")
                .takes_value(true)
                .possible_values(&["error", "warn", "info", "debug", "trace"])
                .default_value("info"),
        );

    let gen_config_cmd = Command::new("gen-config")
        .alias("g")
        .about("generate TEST-ONLY network config")
        .arg(
            Arg::new("peer-count")
                .help("how many peers to generate")
                .takes_value(true)
                .validator(|s| s.parse::<usize>())
                .default_value("2"),
        );

    let app = Command::new("network")
        .about("Network service for CITA-Cloud")
        .subcommands([run_cmd, gen_config_cmd]);

    let matches = app.get_matches();
    match matches.subcommand() {
        Some(("run", m)) => {
            let path = m.value_of("config").unwrap();
            let config = load_config(path).unwrap();

            let log_dir = m.value_of("log-dir");
            let log_file_name = m.value_of("log-file-name");
            let log_level: tracing::Level = m.value_of("log-level").unwrap().parse().unwrap();
            let (writer, _guard) = if m.is_present("stdout") {
                tracing_appender::non_blocking(std::io::stdout())
            } else {
                let log_dir = log_dir.unwrap_or("logs");
                let log_file_name = log_file_name.unwrap_or("network-service.log");
                let file_appender = tracing_appender::rolling::daily(log_dir, log_file_name);
                tracing_appender::non_blocking(file_appender)
            };

            tracing_subscriber::fmt()
                .with_max_level(log_level)
                .with_ansi(false)
                .with_writer(writer)
                .init();

            std::panic::set_hook(Box::new(|panic| {
                if let Some(location) = panic.location() {
                    tracing::error!(
                        message = %panic,
                        panic.file = location.file(),
                        panic.line = location.line(),
                        panic.column = location.column(),
                    );
                } else {
                    tracing::error!(message = %panic);
                }
            }));

            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(Server::setup(config, path.to_string()));
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
