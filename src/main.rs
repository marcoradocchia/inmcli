use clap::Parser;
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm, FuzzySelect, Password, Select};
use spinoff::{spinner, spinners, Color, Spinner, Streams};
use std::{
    ffi::OsStr,
    fmt::Display,
    process::{Command, ExitCode, Output, Stdio},
    str::FromStr,
};

/// CLI options.
#[derive(Debug, Clone, Parser)]
struct Options {
    /// Display WAP `BSSID`.
    #[arg(short, long)]
    bssid: bool,
    /// Display WAP `frequency`.
    #[arg(short, long)]
    frequency: bool,
    /// Display WAP `signal` level as percentage.
    #[arg(short, long)]
    signal: bool,
    /// Display WAP `security`.
    #[arg(short = 'p', long)]
    security: bool,
}

type Result<T> = std::result::Result<T, Error>;
type NmcliResult<T> = std::result::Result<T, NmcliError>;

/// Errors.
#[derive(Debug)]
enum Error {
    Nmcli(NmcliError),
    NmcliCommand(String),
    Frequency,
    Bssid(String),
    Signal,
    WiFiStatus,
    Terminal(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nmcli(error) => write!(
                f,
                "an error occured while executing `nmcli` command: {error}"
            ),
            Self::NmcliCommand(command) => write!(f, "invalid command `{command}`"),
            Self::Frequency => write!(f, "unexpected wlan frequency format"),
            Self::Bssid(bssid) => write!(f, "unable to parse WAP's BSSID `{bssid}`"),
            Self::Signal => write!(f, "unexpected signal format"),
            Self::WiFiStatus => write!(f, "unexpected WiFi status"),
            Self::Terminal(error) => write!(f, "terminal error: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<NmcliError> for Error {
    fn from(error: NmcliError) -> Self {
        Self::Nmcli(error)
    }
}

//// NetworkManager's `nmcli` command errors.
#[derive(Debug)]
enum NmcliError {
    SecretsNotProvided,
    NetworkNotFound,
    NotAuthorized,
    Other(String),
}

impl Display for NmcliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NmcliError::SecretsNotProvided => write!(f, "password not matching or not provided"),
            NmcliError::NetworkNotFound => write!(f, "WiFi network not found"),
            NmcliError::NotAuthorized => write!(f, "not authorized to control networking"),
            NmcliError::Other(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for NmcliError {}

impl From<&str> for NmcliError {
    fn from(s: &str) -> Self {
        match s {
            "Error: Connection activation failed: Secrets were required, but not provided." => {
                NmcliError::SecretsNotProvided
            }
            "Error: Connection activation failed: The Wi-Fi network could not be found." => {
                NmcliError::NetworkNotFound
            }
            "Error: Failed to add/activate new connection: Not authorized to control networking" => {
                NmcliError::NotAuthorized
            }
            s => NmcliError::Other(s.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Frequency {
    GHz(f32),
    MHz(u16),
}

impl FromStr for Frequency {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (value, unit) = s.split_once(' ').ok_or(Error::Frequency)?;
        match unit {
            "MHz" => Ok(Self::MHz(
                value.parse::<u16>().map_err(|_| Error::Frequency)?,
            )),
            "GHz" => Ok(Self::GHz(
                value.parse::<f32>().map_err(|_| Error::Frequency)?,
            )),
            _ => Err(Error::Frequency),
        }
    }
}

impl Frequency {
    /// Return [`Frequency`] as `f32` **GHz** value.
    fn ghz(&self) -> f32 {
        match self {
            Self::MHz(val) => *val as f32 / 1e3,
            Self::GHz(val) => *val,
        }
    }
}

/// WiFi security.
#[derive(Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
enum WiFiSecurity {
    WEP,
    WPA1,
    WPA2,
    WPA3,
    Other(String),
}

impl FromStr for WiFiSecurity {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "WEP" => Self::WEP,
            "WPA1" => Self::WPA1,
            "WPA2" => Self::WPA2,
            "WPA3" => Self::WPA3,
            other => Self::Other(other.to_string()),
        })
    }
}

impl Display for WiFiSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WiFiSecurity::WEP => write!(f, "WEP"),
            WiFiSecurity::WPA1 => write!(f, "WPA1"),
            WiFiSecurity::WPA2 => write!(f, "WPA2"),
            WiFiSecurity::WPA3 => write!(f, "WPA3"),
            WiFiSecurity::Other(code) => write!(f, "{code}"),
        }
    }
}

/// WAP Bssid (MAC address of the WAP).
#[derive(Debug, Clone)]
struct Bssid([u8; 6]);

impl FromStr for Bssid {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bytes = s
            .split(':')
            .map(|byte| -> Result<u8> {
                u8::from_str_radix(byte, 16).map_err(|_| Error::Bssid(s.to_string()))
            })
            .collect::<Result<Vec<u8>>>()?;

        Ok(Bssid(
            bytes.try_into().map_err(|_| Error::Bssid(s.to_string()))?,
        ))
    }
}

impl Display for Bssid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }
}

/// Wireless Access Point info at the time of the scan.
#[derive(Debug, Clone)]
struct WirelessAccessPoint {
    /// Currently active.
    active: bool,
    /// Network SSID.
    ssid: String,
    /// Network BSSID (MAC address of the WAP), 48bits, 6 bytes.
    bssid: Bssid,
    /// WiFi frequency (MHz).
    freq: Frequency,
    /// WiFi signal strenght as percentage.
    signal: u8,
    /// WiFi Security.
    security: Option<Vec<WiFiSecurity>>,
}

impl FromStr for WirelessAccessPoint {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut tokens = Nmcli::parse_line(s);

        Ok(WirelessAccessPoint {
            active: tokens[0] == "yes",
            ssid: tokens.swap_remove(1), // Swap remove to avoid cloning (security is now token 1).
            bssid: Bssid::from_str(&tokens[2])?,
            freq: Frequency::from_str(&tokens[3])?,
            signal: tokens[4].parse::<u8>().map_err(|_| Error::Signal)?,
            security: if tokens[1].is_empty() {
                None
            } else {
                Some(
                    tokens[1]
                        .split(' ')
                        .map(|code| -> Result<WiFiSecurity> { WiFiSecurity::from_str(code) })
                        .collect::<Result<Vec<WiFiSecurity>>>()?,
                )
            },
        })
    }
}

impl Display for WirelessAccessPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ssid)
    }
}

impl WirelessAccessPoint {
    /// Return a [`String`] describing [`WirelessAccessPoint`] info as required.
    fn to_string(&self, options: &Options, ssid_len: usize) -> String {
        let mut wpa_string = vec![];
        wpa_string.push(if self.active { '*' } else { ' ' }.to_string());
        wpa_string.push(format!(
            "{}{:padding$}",
            self.ssid,
            " ",
            padding = ssid_len - self.ssid.len() + 1
        ));

        if options.bssid {
            wpa_string.push(format!("[{}]", self.bssid));
        }

        if options.frequency {
            wpa_string.push(format!("󰖩 {:.1} GHz", self.freq.ghz()))
        }

        if options.signal {
            wpa_string.push(format!("[{:3}%]", self.signal));
        }

        if options.security {
            wpa_string.push(match &self.security {
                Some(security) => format!(
                    " {}",
                    security
                        .iter()
                        .map(|sec| sec.to_string())
                        .collect::<Vec<String>>()
                        .join(", "),
                ),
                None => " ".to_string(),
            })
        }

        wpa_string.join(" ")
    }
}

/// WiFi Status.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum WiFiStatus {
    Enabled,
    Disabled,
}

impl FromStr for WiFiStatus {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            _ => Err(Error::WiFiStatus),
        }
    }
}

impl WiFiStatus {
    /// Return the *negation* (the opposite) of [`WiFiStatus`].
    fn negate(&self) -> WiFiStatus {
        match self {
            Self::Enabled => Self::Disabled,
            Self::Disabled => Self::Enabled,
        }
    }

    /// Return command argument to achieve given [`WiFiStatus`].
    fn to_arg(self) -> String {
        match self {
            Self::Enabled => "on",
            Self::Disabled => "off",
        }
        .to_string()
    }
}

impl WiFiStatus {
    /// Return command `String` associated to [`WiFiStatus`].
    fn to_cmd_string(self) -> String {
        match self {
            Self::Enabled => "Enable",
            Self::Disabled => "Disable",
        }
        .to_string()
    }
}

/// NetworkManager `nmcli` command.
#[derive(Debug)]
struct Nmcli {
    /// Command options.
    options: Options,
    /// WiFi status as [`WiFiStatus`].
    status: WiFiStatus,
    /// Known Wireless Access Points SSIDs.
    known: Vec<String>,
    /// Discovered wireless Access Points.
    waps: Vec<WirelessAccessPoint>,
}

impl Nmcli {
    /// Construct a new [`Nmcli`] instance.
    fn new(options: Options) -> Result<Self> {
        Ok(Self {
            options,
            status: Nmcli::wifi_status()?,
            known: Nmcli::known_waps()?,
            waps: vec![],
        })
    }

    /// Return a vector of [`String`] by parsing `nmcli` **terse** output line:
    /// using the `-t` cli flag, `nmcli` prints output as a `:` separated values table.
    /// `\` is treated as an escape character.
    fn parse_line(line: &str) -> Vec<String> {
        const SEPARATOR: char = ':';
        const ESCAPE: char = '\\';
        let mut tokens: Vec<String> = vec![];
        let mut token = String::new();

        let mut chars = line.chars();
        while let Some(ch) = chars.next() {
            match ch {
                SEPARATOR => {
                    tokens.push(token.clone());
                    token.clear();
                }
                ESCAPE => {
                    if let Some(next_ch) = chars.next() {
                        token.push(next_ch);
                    }
                }
                _ => token.push(ch),
            }
        }

        tokens.push(token);

        tokens
    }

    /// Execute `nmcli` command without collecting any output.
    fn execute<S>(args: &[S]) -> NmcliResult<Output>
    where
        S: AsRef<OsStr>,
    {
        let output = Command::new("nmcli")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(args)
            .spawn()
            .map_err(|error| NmcliError::Other(error.to_string()))?
            .wait_with_output()
            .map_err(|error| NmcliError::Other(error.to_string()))?;

        // Handling command failure.
        if !output.status.success() {
            return Err(NmcliError::from(
                String::from_utf8_lossy(&output.stderr).trim(),
            ));
        }

        Ok(output)
    }

    /// Execute `nmcli` command with specified additional arguments and return its output.
    fn execute_with_output<S>(args: &[S]) -> NmcliResult<String>
    where
        S: AsRef<OsStr>,
    {
        let a: Vec<&OsStr> = ["-t", "-f"]
            .iter()
            .map(OsStr::new)
            .chain(args.iter().map(OsStr::new))
            .collect();

        Ok(String::from_utf8_lossy(&Self::execute(&a)?.stdout)
            .trim()
            .to_string())
    }

    /// Return list of known WAPs SSIDs.
    fn known_waps() -> Result<Vec<String>> {
        Ok(
            Self::execute_with_output(&["name,type", "connection"]).map(|output| {
                output
                    .split('\n')
                    .filter(|line| line.contains("wireless"))
                    .map(|line| Nmcli::parse_line(line).swap_remove(0))
                    .collect()
            })?,
        )
    }

    /// Return WiFis status.
    fn wifi_status() -> Result<WiFiStatus> {
        WiFiStatus::from_str(&Self::execute_with_output(&["wifi", "radio"])?)
    }

    /// Toggle WiFi status.
    fn toggle_wifi(&self) -> Result<()> {
        Self::execute(&["radio", "wifi", &self.status.negate().to_arg()])?;

        Ok(())
    }

    /// Spawn `nmcli` command with required options.
    fn scan(&mut self) -> Result<()> {
        let spinner = Spinner::new_with_stream(
            spinner!(["󰤟 ", "󰤢 ", "󰤥 ", "󰤨 ", "󰤥 ", "󰤢 ", "󰤟 "], 100),
            "Scanning WiFi networks...",
            Color::Cyan,
            Streams::Stderr,
        );

        self.waps = Self::execute_with_output(&[
            "active,ssid,bssid,freq,signal,security",
            "device",
            "wifi",
            "list",
            "--rescan",
            "yes",
        ])?
        .split('\n')
        .map(|s| -> Result<WirelessAccessPoint> { WirelessAccessPoint::from_str(s) })
        .collect::<Result<Vec<WirelessAccessPoint>>>()?;

        spinner.stop_and_persist("✔", Some(Color::Green), "Networks found!");

        Ok(())
    }

    /// Print scanned [`WirelessAccessPoint`]s in table format.
    fn table(&self) -> Vec<String> {
        // Lenght of the longest SSID string.
        // `waps` cannot be empty, so `unwrap` is safe.
        let ssid_len = self.waps.iter().map(|wap| wap.ssid.len()).max().unwrap();
        self.waps
            .iter()
            .map(|wap| wap.to_string(&self.options, ssid_len))
            .collect()
    }

    /// Let user select [`WirelessAccessPoint`].
    fn select(&self) -> Result<Option<&WirelessAccessPoint>> {
        Ok(FuzzySelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose WiFi network")
            .default(0)
            .items(&self.table())
            .interact_opt()
            .map_err(Error::Terminal)?
            .map(|idx| &self.waps[idx]))
    }

    /// Execute `nmcli device wifi connect <bssid> [password <password>] with spinner.
    fn _connect<S>(&self, args: &[S]) -> NmcliResult<()>
    where
        S: AsRef<OsStr>,
    {
        let spinner = Spinner::new_with_stream(
            spinner!(["󰤟 ", "󰤢 ", "󰤥 ", "󰤨 ", "󰤥 ", "󰤢 ", "󰤟 "], 100),
            "Connecting...",
            Color::Cyan,
            Streams::Stderr,
        );

        let result = Self::execute(args);

        match &result {
            Ok(_) => spinner.stop_and_persist("✔", Some(Color::Green), "Connected!"),
            Err(NmcliError::SecretsNotProvided) => {
                spinner.stop_and_persist("", Some(Color::Red), "Wrong password")
            }
            Err(_) => spinner.stop(),
        }

        result?;
        Ok(())
    }

    /// Connect to given [`WirelessAccessPoint`].
    fn connect(&mut self) -> Result<()> {
        // Scan WAPs before trying to connect.
        self.scan()?;

        let wap = match self.select()? {
            Some(wap) => wap,
            None => return Ok(()),
        };

        // If the device is already connected, return.
        if wap.active {
            return Ok(());
        }

        // Arguments to `nmcli` required in oreder to connect a network.
        let mut args: Vec<String> = ["device", "wifi", "connect"]
            .iter()
            .map(|arg| arg.to_string())
            .collect();
        args.push(wap.bssid.to_string());

        // Connection is not known: password is required.
        if wap.security.is_some() && !self.known.contains(&wap.ssid) {
            args.push("password".to_string());

            loop {
                args.push(
                    Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Password")
                        .allow_empty_password(true)
                        .report(false)
                        .interact()
                        .map_err(Error::Terminal)?,
                );

                match self._connect(&args) {
                    Ok(_) => return Ok(()),
                    Err(NmcliError::SecretsNotProvided) => {
                        // Pop wrong password from the `args` vector.
                        args.pop();
                        // Delete connection just saved with wrong password.
                        Self::execute(&["connection", "delete", &wap.ssid])?;
                    }
                    Err(error) => return Err(Error::Nmcli(error)),
                }
            }
        }

        Ok(self._connect(&args)?)
    }

    /// Delete known WAP.
    fn delete(&self) -> Result<()> {
        if let Some(idx) = FuzzySelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose WiFi network to delete")
            .items(&self.known)
            .interact_opt()
            .map_err(Error::Terminal)?
        {
            // Confirmation prompt to avoid accitental delitions.
            if !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Are you sure?")
                .default(false)
                .show_default(true)
                .report(true)
                .wait_for_newline(true)
                .interact()
                .map_err(Error::Terminal)?
            {
                return Ok(());
            }

            Self::execute(&["connection", "delete", &self.known[idx]])?;
        }

        Ok(())
    }

    /// Interactive menu.
    fn menu(&self) -> Result<Option<NmcliCommand>> {
        let commands = NmcliCommand::menu_list(&self.status)?;
        Select::with_theme(&ColorfulTheme::default())
            .items(&commands)
            .default(0)
            .interact_opt()
            .map_err(Error::Terminal)?
            .map(|command| -> Result<NmcliCommand> { NmcliCommand::from_str(&commands[command]) })
            .transpose()
    }
}

/// `nmcli` commands.
#[derive(Debug, Clone, Copy)]
enum NmcliCommand {
    /// Toggle WiFi (`nmcli device wifi radio <on/off>`).
    ToggleWiFi,
    /// Connect to WiFi network.
    Connect,
    /// Delete known WAP from known WAPs list.
    Delete,
}

impl FromStr for NmcliCommand {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Enable WiFi" => Ok(Self::ToggleWiFi),
            "Disable WiFi" => Ok(Self::ToggleWiFi),
            "Connect to WiFi network" => Ok(Self::Connect),
            "Delete WiFi network" => Ok(Self::Delete),
            command => Err(Error::NmcliCommand(command.to_string())),
        }
    }
}

impl NmcliCommand {
    /// Return command `String` associated to [`NmcliCommand`].
    fn to_cmd_string(self) -> Result<String> {
        Ok(match self {
            Self::ToggleWiFi => format!("{} WiFi", Nmcli::wifi_status()?.negate().to_cmd_string()),
            Self::Connect => "Connect to WiFi network".to_string(),
            Self::Delete => "Delete WiFi network".to_string(),
        })
    }
}

impl NmcliCommand {
    /// Return a menu list based on [`WiFiStatus`].
    fn menu_list(wifi_status: &WiFiStatus) -> Result<Vec<String>> {
        let mut menu = vec![Self::ToggleWiFi, Self::Delete];
        if *wifi_status == WiFiStatus::Enabled {
            menu.insert(1, Self::Connect);
        }

        menu.into_iter()
            .map(|command| command.to_cmd_string())
            .collect()
    }
}

fn run(options: Options) -> Result<()> {
    let mut nmcli = Nmcli::new(options)?;
    match nmcli.menu()? {
        Some(NmcliCommand::ToggleWiFi) => nmcli.toggle_wifi()?,
        Some(NmcliCommand::Connect) => nmcli.connect()?,
        Some(NmcliCommand::Delete) => nmcli.delete()?,
        None => {}
    }

    Ok(())
}

fn main() -> ExitCode {
    let options = Options::parse();

    if let Err(error) = run(options) {
        eprintln!("{} {error}", "Error:".red().bold());
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
