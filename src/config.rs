use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about = "Deploy a Synchronic Web Journal Software Development Kit (SDK) as a local webserver")]
pub struct Config {
    #[arg(short, long, default_value_t = String::from(""), help = "Path to the persistent database")]
    pub database: String,

    #[arg(short, long, default_value_t = 4096, help = "Port to access the webserver")]
    pub port: u16,

    #[arg(short, long, default_value_t = String::from(""), help = "Initial script to pass into the Journal")]
    pub boot: String,
}

impl Config {
    pub fn new() -> Self {
        Config::parse()
    }
}
