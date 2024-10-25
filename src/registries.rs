const REGISTRY_PATTERN: &str = r"(?i)(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|[A-Z][A-Z0-9_]*)(\\[A-Za-z0-9_. ]+)+";
const REGISTRY: &[&str] = &[
            r"(?mxi)",
            r"(?!^.*?(?:\^.*$",
            r"|\[\d\-\d\]|\{\d*\,\d*\}))((^[^\n]*?)((^\\*|\\+)",
            r"(HK(EY|LM|CU|U|CC|CR))",
            r"(\\+|_[^\n]+?\\+)|",
            r"^(BCD[-\n]+|",
            r"COMPONENTS|DRIVERS|ELAM|HARDWARE|SAM|Schema|SECURITY|SOFTWARE|SYSTEM|AppEvents|Console|Control( Panel)?",
            r"|Secrets|Environment|EUDC|Keyboard Layout|Network|Printers|Uninstall|Volatile Environment)\\|",
            r"(^\\*|\\+)S\-\d+[^\n]*?\\+|",
            r"\[(Install Path|[Music Path]|Pictures Path|Videos Path|Artist|App Data Path|Name)\]|",
            "\"AppliesTo\"|\"AssociateFiles\"|",
            r"\[App Data Path\]|",
            "\"Common\"|\"CommonEmojiTerminators\"|\"Complete\"|",
            "\"(Configuration|DefaultFeature|Description|DiskPrompt|DocumentationShortcuts|EnvironmentPathNode|EnvironmentPathNpmModules|Extensions|External Program Arguments|File Location.*?|MainApplication|MainFeature|NodeRuntime|Path|Servicing_Key|Shortcuts)\")",
            r"([^\n#]*?)\\*\S+)",
            r"($|[^\\]+$)",
        ];

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde_support", derive(Serialize))]

pub enum RegistryIOC<'r> {
    Registry(&'r str),
}

pub fn parse_registry(input: &str) -> Vec<RegistryIOC> {
    lazy_static! {
        static ref REGISTRY_RE: fancy_regex::Regex =
            fancy_regex::Regex::new(&REGISTRY_PATTERN).unwrap();
    }

    REGISTRY_RE
        .find_iter(input)
        .filter_map(|x| x.ok())
        .filter(|x| is_valid_registry(x.as_str()))
        .map(|m| RegistryIOC::Registry(m.as_str()))
        .collect()
}

fn is_valid_registry(input: &str) -> bool {
    lazy_static! {
        static ref REGISTRY_RE_RE: fancy_regex::Regex =
            fancy_regex::Regex::new(&REGISTRY.join("")).unwrap();
    }

    REGISTRY_RE_RE.is_match(input).unwrap_or(false)
}

#[test]
fn test_is_registry_key() {
    assert_eq!(
        parse_registry("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
        vec![RegistryIOC::Registry(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        )]
    );

    assert_eq!(
        parse_registry("YIKES SOFTWARE\\Microsoft\\Windows\\CurrentVersion"),
        vec![RegistryIOC::Registry(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        )]
    );

    assert_eq!(
        parse_registry("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"),
        vec![RegistryIOC::Registry(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        )]
    );

    // invalid
    assert_eq!(parse_registry("This\nIs\\aRegistryKey"), vec![]);
    assert_eq!(parse_registry("^[U][0-9]{12,15}$"), vec![]);
}
