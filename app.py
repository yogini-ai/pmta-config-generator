import ipaddress
import re
import streamlit as st

st.set_page_config(page_title="PMTA Config Generator", page_icon="🛠️", layout="centered")

st.title("PMTA Configuration Generator")
st.caption("Generate reviewable virtual-MTA configuration blocks from IPs you are authorized to use.")

st.warning(
    "This tool only generates text; it does not connect to PMTA or send email. "
    "Use only IP addresses and domains you control or are authorized to administer. "
    "Review the output with your mail administrator before deploying."
)

with st.form("config_form"):
    st.subheader("1. IP addresses")
    mode = st.radio("How will you provide IPs?", ["Starting IPv4 + count", "Paste IP addresses"], horizontal=False)

    start_ip = ""
    count = 1
    pasted_ips = ""
    if mode == "Starting IPv4 + count":
        start_ip = st.text_input("Starting IPv4 address", placeholder="192.0.2.10")
        count = st.number_input("Number of consecutive IPs", min_value=1, max_value=256, value=4, step=1)
    else:
        pasted_ips = st.text_area("One IP address per line", placeholder="192.0.2.10\n192.0.2.11", height=120)

    st.subheader("2. VMTA and hostname")
    vmta_prefix = st.text_input("VMTA prefix", value="outbound")
    hostname_words = st.text_area(
        "Hostname labels — one per line (must match number of IPs)",
        placeholder="Maple\nCedar\nWillow\nJuniper",
        height=120,
    )
    hostname_domain = st.text_input("Hostname domain suffix", placeholder="mail.example.com")

    st.subheader("3. DKIM domain-key")
    selector = st.text_input("DKIM selector", placeholder="selector1")
    signing_domain = st.text_input("Signing domain", placeholder="example.com")
    key_directory = st.text_input("Private-key directory", value="/var/pmtadomain-keys")

    submitted = st.form_submit_button("Generate configuration", type="primary", use_container_width=True)

def safe_label(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", value))

def safe_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    parts = value.rstrip(".").split(".")
    return all(safe_label(p) for p in parts)

if submitted:
    errors = []
    ips = []

    if mode == "Starting IPv4 + count":
        try:
            first = ipaddress.ip_address(start_ip.strip())
            if first.version != 4:
                errors.append("Please enter an IPv4 address.")
            else:
                for offset in range(int(count)):
                    candidate = int(first) + offset
                    if candidate > int(ipaddress.IPv4Address("255.255.255.255")):
                        errors.append("The requested range exceeds the IPv4 address limit.")
                        break
                    ips.append(str(ipaddress.IPv4Address(candidate)))
        except ValueError:
            errors.append("Enter a valid starting IPv4 address.")
    else:
        raw_ips = [line.strip() for line in pasted_ips.splitlines() if line.strip()]
        if not raw_ips:
            errors.append("Paste at least one IP address.")
        for raw in raw_ips:
            try:
                parsed = ipaddress.ip_address(raw)
                if parsed.version != 4:
                    errors.append(f"{raw}: only IPv4 addresses are supported in this version.")
                else:
                    ips.append(str(parsed))
            except ValueError:
                errors.append(f"{raw}: invalid IP address.")
        if len(set(ips)) != len(ips):
            errors.append("Duplicate IP addresses were found.")

    words = [line.strip() for line in hostname_words.splitlines() if line.strip()]
    if not vmta_prefix or not re.fullmatch(r"[A-Za-z0-9_-]+", vmta_prefix):
        errors.append("VMTA prefix may contain only letters, numbers, underscores, and hyphens.")
    if len(words) != len(ips) and ips:
        errors.append(f"Provide exactly {len(ips)} hostname labels; you provided {len(words)}.")
    for word in words:
        if not safe_label(word):
            errors.append(f"Invalid hostname label: {word!r}. Use letters, numbers, or hyphens.")
    if not safe_domain(hostname_domain):
        errors.append("Enter a valid hostname domain suffix, e.g. mail.example.com.")
    if not safe_label(selector):
        errors.append("Enter a valid DKIM selector (letters, numbers, or hyphens).")
    if not safe_domain(signing_domain):
        errors.append("Enter a valid signing domain, e.g. example.com.")
    if not key_directory.startswith("/") or "\n" in key_directory or "\r" in key_directory:
        errors.append("Key directory must be an absolute path, e.g. /var/pmtadomain-keys.")

    if errors:
        st.error("Please correct these issues:")
        for error in errors:
            st.write(f"- {error}")
    else:
        lines = [
            "# Generated draft — review before deploying.",
            "# Confirm IP ownership, DNS/PTR, SPF, DKIM, DMARC, and local PMTA syntax.",
            ""
        ]
        for ip, word in zip(ips, words):
            vmta_name = f"{vmta_prefix}_{ip.replace('.', '_')}"
            hostname = f"{word}.{hostname_domain.rstrip('.')}"
            key_path = f"{key_directory.rstrip('/')}/{selector}.{signing_domain}.pem"
            lines.extend([
                f"<virtual-mta {vmta_name}>",
                f"    smtp-source-host {ip} {hostname}",
                f"    domain-key {selector},{signing_domain},{key_path}",
                "</virtual-mta>",
                ""
            ])
        output = "\n".join(lines).rstrip() + "\n"
        st.success(f"Generated {len(ips)} virtual-MTA block(s).")
        st.caption("Click the copy icon in the top-right corner of the configuration box to copy everything to your clipboard.")
        st.code(output, language=None)
        st.download_button(
            "Download pmta_config.txt",
            data=output,
            file_name="pmta_config.txt",
            mime="text/plain",
            use_container_width=True,
        )
        st.info(
            "This is a template, not a full PMTA configuration. Confirm the hostname format, "
            "domain-key syntax, and key-file naming against your installed PMTA version and existing config."
        )

st.divider()
st.caption("Privacy note: this app does not intentionally store the values you enter. On hosted platforms, follow the host's privacy and access settings.")
