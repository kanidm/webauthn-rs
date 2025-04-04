#[cfg(test)]
mod tests {
    use anyhow::{Error, Result};
    use serde_json::Value;
    use std::fs::File;
    use std::process::{Command, Stdio};

    fn run(subcommand: &str, input_file: &str) -> Result<Value, Error> {
        let output = Command::new("cargo")
            .arg("run")
            .arg("--")
            .arg("--pretty-print")
            .arg(subcommand)
            .stdin(Stdio::from(File::open(input_file)?))
            .output()
            .expect("failed to execute process");

        Ok(serde_json::from_str(
            String::from_utf8_lossy(&output.stdout).as_ref(),
        )?)
    }

    #[test]
    fn test_register_start() -> Result<(), Error> {
        let v = run("register-start", "tests/data/register-start.json")?;

        assert!(v.get("error").is_none());
        assert!(v["client"].is_object());
        assert!(v["client"]["publicKey"].is_object());
        assert!(v["server"].is_object());
        assert!(v["server"]["rs"]["challenge"].is_string());
        Ok(())
    }

    #[test]
    fn test_register_finish() -> Result<(), Error> {
        let v = run("register-finish", "tests/data/register-finish.json")?;

        assert!(v.get("client").is_none());
        assert!(v.get("error").is_none());
        assert!(v["server"].is_object());
        assert!(v["server"]["cred"]["cred_id"].is_string());
        Ok(())
    }

    #[test]
    fn test_authenticate_start() -> Result<(), Error> {
        let v = run("authenticate-start", "tests/data/authenticate-start.json")?;

        assert!(v.get("error").is_none());
        assert!(v["client"].is_object());
        assert!(v["client"]["publicKey"].is_object());
        assert!(v["server"].is_object());
        assert!(v["server"]["ast"]["credentials"].is_array());
        Ok(())
    }

    #[test]
    fn test_authenticate_finish() -> Result<(), Error> {
        let v = run("authenticate-finish", "tests/data/authenticate-finish.json")?;

        assert!(v.get("client").is_none());
        assert!(v.get("error").is_none());
        assert!(v["server"].is_object());
        assert!(v["server"]["cred_id"].is_string());
        Ok(())
    }

    #[test]
    fn test_authenticate_finish_fail() -> Result<(), Error> {
        let v = run(
            "authenticate-finish",
            "tests/data/authenticate-finish-fail.json",
        )?;

        assert_eq!(
            v["error"],
            "missing field `credentials` at line 40 column 5"
        );
        Ok(())
    }
}
