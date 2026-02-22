mod cli;

fn main() {
    let cli = cli::parse();
    cli::run(cli);
}
