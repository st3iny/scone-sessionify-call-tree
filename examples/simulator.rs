use anyhow::{bail, Result};
use scone_sessionify_call_tree::gen_and_exec;

/**
 * Simple simulator that takes an array of env vars (KEY=VAL) and args from the command line and
 * invokes the scone_sessionify_call_tree library. The library will then create a SCONE policy on
 * the fly, fork and finally exec the target binary with the supplied env and args.
 *
 * This logic is ideally implemented in the SCONE runtime.
 */

#[tokio::main]
async fn main() -> Result<()> {
    let mut std_args_iter = std::env::args().skip(1);

    let mut env = Vec::new();
    let mut args = Vec::new();
    for arg in &mut std_args_iter {
        if !arg.contains('=') {
            args.push(arg);
            break;
        }

        env.push(arg);
    }

    args.extend(std_args_iter);
    if args.is_empty() {
        bail!("No args given");
    }

    gen_and_exec(&args, &env).await?;
    unreachable!("Exec failed but did not return Result::Err!");
}
