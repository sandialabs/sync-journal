use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Deploy a Synchronic Web Journal Software Development Kit (SDK) as a local webserver"
)]
pub struct Config {
    #[arg(short, long, default_value_t = String::from(""), help = "Path to the persistent database")]
    pub database: String,

    #[arg(
        short,
        long,
        default_value_t = 4096,
        help = "Port to access the webserver"
    )]
    pub port: u16,

    #[arg(short, long, default_value_t = String::from(""), help = "Initial script to pass into the Journal")]
    pub boot: String,

    #[arg(short, long, default_value_t = String::from(""), help = "If set, then evaluate the provided query, print, and exit immediately")]
    pub evaluate: String,

    #[arg(short, long, default_value_t = String::from(""), help = "Contents of the step query")]
    pub step: String,

    #[arg(
        short = 'c',
        long,
        default_value_t = 0,
        help = "Power of two determining the period of the step query"
    )]
    pub periodicity: i32,
}

impl Config {
    pub fn new() -> Self {
        Config::parse()
    }
}
