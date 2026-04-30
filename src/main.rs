use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "proxy", about = "NetProxy VPN CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(short = 'p', long = "port", default_value_t = 6767)]
        port: u16,

        #[arg(long = "password")]
        password: String
    },
    Connect {
        ip: String,

        #[arg(short = 'p', long = "port")]
        port: u16,

        #[arg(long = "password")]
        password: String
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { port, password } => {
            server::run_server(password, port);
        }
        Commands::Connect { ip, port, password } => {
            client::run_client(password, ip, port);
        }
    }
}