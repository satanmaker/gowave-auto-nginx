#!/usr/bin/env bash
# modules/geoip.sh - the exit country of a traffic node
#
# The country is a label for the operator's subscription, never a routing
# decision: nothing here changes where a connection goes. Detection is one
# bounded request made from the node's own outbound address, and what is stored
# is the code the operator confirmed or typed.
set -Eeuo pipefail

_geoip_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=modules/i18n.sh
source "$_geoip_dir/i18n.sh"

# The one endpoint a lookup may ask. A plain-text answer keeps the parser a
# two-letter check instead of a JSON reader on a freshly provisioned Worker, and
# the operator can point it at another service when this one is unavailable.
GOWAVE_COUNTRY_LOOKUP_URL="${GOWAVE_COUNTRY_LOOKUP_URL:-https://ipinfo.io/country}"
GOWAVE_COUNTRY_LOOKUP_TIMEOUT="${GOWAVE_COUNTRY_LOOKUP_TIMEOUT:-5}"

# Where the country question is printed. Onboarding captures a Worker's stderr,
# so the SSH path points this at the terminal it has already bound.
GOWAVE_COUNTRY_PROMPT_OUT="${GOWAVE_COUNTRY_PROMPT_OUT:-/dev/stderr}"

# The assigned ISO 3166-1 alpha-2 codes, space-separated. Only an assigned code
# is a country: a service answering `UK`, `EU` or nothing leaves the question to
# the operator instead of inventing a flag.
country_assigned_codes() {
    printf '%s' 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DO DZ EC EE EG EH ER ES ET
FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT
JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ
LA LB LC LI LK LR LS LT LU LV LY
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ OM
PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA
RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'
}

# An uppercase assigned code, or nothing.
country_is_assigned() {
    local code="$1" assigned
    [[ "$code" =~ ^[A-Z]{2}$ ]] || return 1
    # The table is wrapped for reading, so the separator before a code is a space
    # or a newline: flattened here, every assigned code is reachable, including
    # the first one on each line.
    assigned=" $(country_assigned_codes) "
    assigned="${assigned//$'\n'/ }"
    [[ "$assigned" == *" $code "* ]]
}

# An answer or a lookup answer as an assigned code: spaces and case are
# irrelevant, anything else is nothing.
country_normalize() {
    local text="${1:-}"
    text="${text//[[:space:]]/}"
    text="${text^^}"
    if country_is_assigned "$text"; then
        printf '%s' "$text"
    fi
    return 0
}

# The answer text from a lookup service as an assigned code, or nothing. The
# parser reads one line and accepts it only when it is a bare code, so a service
# that starts answering prose or JSON falls back to the operator rather than
# producing a country from a fragment.
country_parse() {
    local line=""
    IFS= read -r line || true
    country_normalize "$line"
}

# Whether this run may ask at all. Only the interactive wizard sets this: a
# positional install must neither prompt nor contact a lookup service, and no
# lookup happens anywhere without it.
country_asking() {
    [[ "${GOWAVE_COUNTRY_ASK:-}" == "yes" ]]
}

# One bounded request from this host's own outbound address.
#
# The service sees the host's source address and the request itself; no name,
# domain, token or credential is sent. A failed request prints nothing and is not
# an error: the operator is asked instead.
country_lookup_here() {
    local url="$GOWAVE_COUNTRY_LOOKUP_URL" limit="$GOWAVE_COUNTRY_LOOKUP_TIMEOUT"
    local text=""
    if command -v curl >/dev/null 2>&1; then
        text=$(curl -fsS --max-time "$limit" "$url" 2>/dev/null) || text=""
    elif command -v wget >/dev/null 2>&1; then
        text=$(wget -qO- --timeout="$limit" "$url" 2>/dev/null) || text=""
    fi
    [[ -n "$text" ]] || return 0
    printf '%s\n' "$text" | country_parse
}

# The same single request written for the node that must make it. A Worker has no
# route through this host's tools, so it runs this over the SSH session that is
# already open, and the answer describes the Worker's own outbound address.
country_lookup_command() {
    printf 'url=%q\n' "$GOWAVE_COUNTRY_LOOKUP_URL"
    printf 'limit=%q\n' "$GOWAVE_COUNTRY_LOOKUP_TIMEOUT"
    cat <<'LOOKUP'
if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time "$limit" "$url" 2>/dev/null || true
elif command -v wget >/dev/null 2>&1; then
    wget -qO- --timeout="$limit" "$url" 2>/dev/null || true
fi
LOOKUP
}

# The regional-indicator pair an assigned code renders as, or nothing.
country_flag() {
    local code="$1" out="" i letter prefix hex
    local alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local base=$(( 0x1F1E6 ))
    country_is_assigned "$code" || return 0
    for (( i = 0; i < 2; i++ )); do
        letter="${code:i:1}"
        prefix="${alphabet%%"$letter"*}"
        hex=$(printf '%08X' $(( base + ${#prefix} )))
        out+=$(printf '%b' "\\U$hex")
    done
    printf '%s' "$out"
}

# The country's name in the wizard's language. The catalog carries the names it
# holds; an assigned code it does not name is shown as the code, which is still
# unambiguous next to the flag.
country_name() {
    local code name
    code=$(country_normalize "${1:-}")
    [[ -n "$code" ]] || return 0
    name=$(t "country.${code,,}")
    if [[ "$name" == "country.${code,,}" ]]; then
        printf '%s' "$code"
    else
        printf '%s' "$name"
    fi
}

# Ask for one node's exit country.
#
# Enter confirms the suggestion; a typed code overrides it in any case; empty or
# invalid input repeats only this question, and an empty answer without a
# suggestion is refused rather than turned into a country. Returns 1 only when
# the operator's input ended, which callers treat as "no country", never as a
# reason to abort an installation.
#
# Args: node label, suggestion
country_confirm() {
    local label="$1" suggestion answer code
    suggestion=$(country_normalize "${2:-}")
    printf '%s\n' "$(tf wizard.country.disclosure "$GOWAVE_COUNTRY_LOOKUP_URL")" \
        > "$GOWAVE_COUNTRY_PROMPT_OUT"
    while true; do
        if [[ -n "$suggestion" ]]; then
            printf '%s\n' "$(tf wizard.country.presented "$label" \
                "$(country_flag "$suggestion")" "$(country_name "$suggestion")" "$suggestion")" \
                > "$GOWAVE_COUNTRY_PROMPT_OUT"
            printf '%s' "$(t wizard.country.prompt)" > "$GOWAVE_COUNTRY_PROMPT_OUT"
        else
            printf '%s\n' "$(tf wizard.country.manual "$label")" > "$GOWAVE_COUNTRY_PROMPT_OUT"
        fi
        if ! IFS= read -r answer; then
            printf '\n' > "$GOWAVE_COUNTRY_PROMPT_OUT"
            return 1
        fi
        if [[ -z "$answer" ]]; then
            if [[ -n "$suggestion" ]]; then
                printf '%s' "$suggestion"
                return 0
            fi
            printf '%s\n' "$(t wizard.country.invalid)" > "$GOWAVE_COUNTRY_PROMPT_OUT"
            continue
        fi
        code=$(country_normalize "$answer")
        if [[ -n "$code" ]]; then
            # A correction is shown back the way a suggestion is: the operator
            # reads the country this code means before the label is used, and a
            # code typed over the suggestion is the one that gets stored.
            if [[ "$code" != "$suggestion" ]]; then
                printf '%s\n' "$(tf wizard.country.presented "$label" \
                    "$(country_flag "$code")" "$(country_name "$code")" "$code")" \
                    > "$GOWAVE_COUNTRY_PROMPT_OUT"
            fi
            printf '%s' "$code"
            return 0
        fi
        printf '%s\n' "$(t wizard.country.invalid)" > "$GOWAVE_COUNTRY_PROMPT_OUT"
    done
}
