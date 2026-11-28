#!/usr/bin/env bash
# modules/draft.sh - the durable, secret-free deployment draft
#
# The wizard collects a plan over several minutes and then spends a great deal
# more of them installing it. An interruption used to cost every answer, and a
# restart could not tell a half-finished deployment from an untouched host.
# This module is the shell side of `modules/deployment_state.py`: it turns the
# `GOWAVE_PLAN_*` variables into the plan document, restores them from it, and
# records one checkpoint per Panel, local node and remote node.
#
# Only answers the operator gave, and the verdicts the installer reached, are
# written. Passwords, keys and temporary SSH material never reach the draft:
# the schema refuses unknown fields, and this module has none to offer.
#
# A host without python3 still installs. Draft persistence is an aid, not a
# prerequisite, so every function here degrades to a no-op when the store
# cannot run, and no installation step depends on it.
set -Eeuo pipefail

_draft_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Where the draft lives. The tests point it at a temporary directory; the
# installer keeps the system path the operator guides document.
_draft_default_path="/var/lib/gowave-auto-nginx/deployment/active.json"
GOWAVE_DRAFT_PATH="${GOWAVE_DRAFT_PATH:-$_draft_default_path}"
# `install` for the setup wizard, `node_add` for the menu's add-node path.
GOWAVE_DRAFT_KIND="${GOWAVE_DRAFT_KIND:-install}"
# Set to 1 by `draft_offer_resume` when this process continued a saved plan:
# the install reads it to decide whether verified components may be checked
# instead of built again.
GOWAVE_DRAFT_RESUMED=0
GOWAVE_DRAFT_OPERATION=""
GOWAVE_DRAFT_REVIEWED="no"

draft_installer_revision() {
    local root revision
    if [[ -n "${GOWAVE_INSTALLER_REVISION:-}" ]]; then
        printf '%s' "$GOWAVE_INSTALLER_REVISION"
        return 0
    fi
    root=$(cd "$_draft_dir/.." && pwd)
    revision=$(git -C "$root" rev-parse --short HEAD 2>/dev/null </dev/null || true)
    printf '%s' "${revision:-unknown}"
}

_draft_available() {
    command -v python3 >/dev/null 2>&1 && [[ -f "$_draft_dir/deployment_state.py" ]] || return 1
    # The system draft is root's: its directory is private to the owner the
    # installer runs as. An unprivileged invocation has no draft to keep and
    # must not fail over one, so it installs exactly as it did before drafts
    # existed. A caller that names its own path — the tests — is unaffected.
    if [[ "$GOWAVE_DRAFT_PATH" == "$_draft_default_path" ]] && (( EUID != 0 )); then
        return 1
    fi
    return 0
}

# One process boundary, one JSON document each way: the store owns the schema,
# the locking and the atomic replace, and this module owns nothing but the
# translation.
_draft_cli() {
    local root
    root=$(cd "$_draft_dir/.." && pwd)
    PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}" \
        python3 -m modules.deployment_state --path "$GOWAVE_DRAFT_PATH" "$@"
}

# An empty answer is written as `-` and read back as the empty string, because
# `read` would otherwise collapse the tab that ends the line.
_draft_blank() {
    if [[ "$1" == "-" ]]; then
        printf ''
    else
        printf '%s' "$1"
    fi
}

# The accepted answers as the plan document, for `--plan` and `--save`.
#
# A plan that has not reached a topology is not a draft: the schema requires
# one, and a document without it would fail validation rather than record
# progress. The caller saves after every accepted answer, so an interruption
# during collection keeps the answers given so far.
draft_plan_document() {
    local -a node_arguments=()
    local i
    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        node_arguments+=(
            "${GOWAVE_PLAN_NODE_NAMES[$i]:-}"
            "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]:-}"
            "${GOWAVE_PLAN_NODE_VISION[$i]:-}"
            "${GOWAVE_PLAN_NODE_LABELS[$i]:-}"
        )
    done
    python3 - \
        "$GOWAVE_DRAFT_KIND" "${GOWAVE_PLAN_VARIANT:-}" "$(wizard_language)" \
        "$(draft_installer_revision)" \
        "${GOWAVE_PLAN_PANEL_NAME:-}" "${GOWAVE_PLAN_CAMOUFLAGE_NAME:-}" "${GOWAVE_PLAN_VISION_NAME:-}" \
        "${GOWAVE_PLAN_COVER_NAME:-}" "${GOWAVE_PLAN_COVER_WWW:-}" "${GOWAVE_PLAN_EMAIL:-}" \
        "${GOWAVE_PLAN_LOCAL_LABEL:-}" "${node_arguments[@]}" <<'PY'
import json
import sys

(kind, topology, language, revision, panel, camouflage, vision, cover,
 cover_www, email, local_label, *nodes) = sys.argv[1:]


def present(value):
    return value if value else None


answers = {}
for key, value in (('name', local_label), ('primary_domain', panel),
                   ('reality_domain', camouflage), ('vision_domain', vision),
                   ('cover_domain', cover), ('email', email)):
    if present(value):
        answers[key] = value
if cover_www in ('yes', 'no'):
    answers['cover_www'] = cover_www == 'yes'

collection = {}
for position in range(0, len(nodes), 4):
    name, node_camouflage, node_vision, label = nodes[position:position + 4]
    node = {}
    for key, value in (('name', label), ('primary_domain', name),
                       ('reality_domain', node_camouflage), ('vision_domain', node_vision)):
        if present(value):
            node[key] = value
    collection['node-%d' % (position // 4 + 1)] = node

json.dump({
    'kind': kind,
    'topology': topology,
    'language': language,
    'installer_revision': revision,
    'answers': answers,
    'nodes': collection,
}, sys.stdout)
PY
}

# Record the plan as the draft. `--reviewed` marks the operator's authorization
# of exactly these answers; an edit afterwards is saved without it, which is how
# a corrected plan loses its authorization and has to pass review again.
draft_save_plan() {
    local document
    if [[ -z "${GOWAVE_PLAN_VARIANT:-}" ]]; then
        return 0
    fi
    _draft_available || return 0
    document=$(draft_plan_document) || return 1
    if [[ "${1:-}" == "--reviewed" ]]; then
        printf '%s' "$document" | _draft_cli --plan --reviewed >/dev/null
    else
        printf '%s' "$document" | _draft_cli --plan >/dev/null
    fi
}

# Print the stored draft. 0 and the document, 3 when there is none, 4 when
# another installer holds it, 1 when it cannot be read.
draft_load() {
    _draft_available || return 3
    _draft_cli --load
}

# The installer revision that wrote the draft on stdin.
#
# The store refuses to rewrite a draft that another revision saved, because a
# plan is only meaningful in the vocabulary that collected it. A resume has to
# reach the same verdict before it restores anything, or every answer the
# operator gives would be accepted and then silently lost to that refusal.
draft_document_revision() {
    python3 -c '
import json
import sys

print(json.load(sys.stdin)["installer_revision"])
'
}

draft_discard() {
    _draft_available || return 0
    _draft_cli --discard
}

# Forget the draft. The deployment it described is left exactly as it is: an
# abandoned plan is not an uninstall, a compensation or a rerun.
draft_abandon() {
    draft_discard >/dev/null 2>&1 || true
    return 0
}

# The draft on stdin as the tab-separated lines `draft_restore` reads.
_draft_restore_lines() {
    python3 -c '
import json
import sys

document = json.load(sys.stdin)


def value(text):
    return text if text else "-"


answers = document["answers"]
print("variant\t" + document["topology"])
print("language\t" + document["language"])
print("operation\t" + document["operation_id"])
print("reviewed\t" + ("yes" if document["reviewed_digest"] else "no"))
for key in ("name", "primary_domain", "reality_domain", "vision_domain", "cover_domain", "email"):
    if key in answers:
        print("answer\t%s\t%s" % (key, value(answers[key])))
if "cover_www" in answers:
    print("answer\tcover_www\t" + ("yes" if answers["cover_www"] else "no"))
for identity in sorted(document["nodes"], key=lambda item: int(item.split("-")[1])):
    node = document["nodes"][identity]
    print("node\t%s\t%s\t%s\t%s\t%s" % (
        identity.split("-")[1],
        value(node.get("primary_domain")),
        value(node.get("reality_domain")),
        value(node.get("vision_domain")),
        value(node.get("name")),
    ))
'
}

# Restore the plan variables from the draft on stdin.
#
# The store has already validated every value, so these lines carry no tab and
# no newline by construction: an answer the schema would refuse cannot reach
# the shell.
draft_restore() {
    local lines line index
    local -a fields=()
    lines=$(_draft_restore_lines) || return 1
    GOWAVE_PLAN_NODE_COUNT=0
    GOWAVE_PLAN_NODE_NAMES=()
    GOWAVE_PLAN_NODE_CAMOUFLAGE=()
    GOWAVE_PLAN_NODE_VISION=()
    GOWAVE_PLAN_NODE_LABELS=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        fields=()
        IFS=$'\t' read -r -a fields <<< "$line"
        case "${fields[0]:-}" in
            variant) GOWAVE_PLAN_VARIANT="${fields[1]}" ;;
            language) GOWAVE_WIZARD_LANG="${fields[1]}" ;;
            operation) GOWAVE_DRAFT_OPERATION="${fields[1]}" ;;
            reviewed) GOWAVE_DRAFT_REVIEWED="${fields[1]}" ;;
            answer)
                case "${fields[1]}" in
                    name) GOWAVE_PLAN_LOCAL_LABEL="${fields[2]}" ;;
                    primary_domain) GOWAVE_PLAN_PANEL_NAME="${fields[2]}" ;;
                    reality_domain) GOWAVE_PLAN_CAMOUFLAGE_NAME="${fields[2]}" ;;
                    vision_domain) GOWAVE_PLAN_VISION_NAME="${fields[2]}" ;;
                    cover_domain) GOWAVE_PLAN_COVER_NAME="${fields[2]}" ;;
                    cover_www) GOWAVE_PLAN_COVER_WWW="${fields[2]}" ;;
                    email) GOWAVE_PLAN_EMAIL="${fields[2]}" ;;
                esac
                ;;
            node)
                index=$((fields[1] - 1))
                GOWAVE_PLAN_NODE_NAMES[index]=$(_draft_blank "${fields[2]}")
                GOWAVE_PLAN_NODE_CAMOUFLAGE[index]=$(_draft_blank "${fields[3]}")
                GOWAVE_PLAN_NODE_VISION[index]=$(_draft_blank "${fields[4]}")
                GOWAVE_PLAN_NODE_LABELS[index]=$(_draft_blank "${fields[5]}")
                GOWAVE_PLAN_NODE_COUNT="${fields[1]}"
                ;;
        esac
    done <<< "$lines"
    # The Panel's Vision answer is a property of the vision name, and the
    # summary and review read it as one.
    if [[ -n "${GOWAVE_PLAN_VISION_NAME:-}" ]]; then
        GOWAVE_PLAN_PANEL_VISION="yes"
    fi
    return 0
}

# Load the stored draft and restore it into this shell. The document is read
# into a variable first: a pipe would run `draft_restore` in a subshell and
# every assignment would be forgotten with it.
draft_restore_saved() {
    local document
    document=$(draft_load) || return $?
    draft_restore <<< "$document"
}

# Write one checkpoint. The state, stage and attempt come from the caller and
# are the schema's own vocabulary; the store refuses anything else, so a typo
# here is a rejected write rather than a record that lies.
draft_checkpoint() {
    local identity="$1" state_value="$2" stage="$3" attempt="${4:-0}" node_uuid="${5:-}"
    local payload
    if [[ -z "${GOWAVE_PLAN_VARIANT:-}" ]] || ! _draft_available; then
        return 0
    fi
    payload=$(printf '{"state":"%s","stage":"%s","attempt":%s' \
        "$state_value" "$stage" "$attempt")
    if [[ -n "$node_uuid" ]]; then
        payload+=$(printf ',"node_uuid":"%s"' "$node_uuid")
    fi
    payload+='}'
    printf '%s' "$payload" | _draft_cli --checkpoint "$identity" >/dev/null
}

# One component's recorded state, or `missing` when the draft has no such
# checkpoint. The install reads this to decide what is already confirmed, so an
# unreadable draft answers `missing` and the component is worked on again.
draft_checkpoint_state() {
    draft_checkpoint_field "$1" state
}

draft_checkpoint_field() {
    local identity="$1" field="$2" document
    if ! document=$(draft_load 2>/dev/null); then
        printf 'missing'
        return 0
    fi
    python3 -c '
import json
import sys

document = json.load(sys.stdin)
checkpoint = document["checkpoints"].get(sys.argv[1], {})
print(checkpoint.get(sys.argv[2], "missing"), end="")
' "$identity" "$field" <<< "$document"
}
