#!/usr/bin/env bash
# modules/i18n.sh - message catalog for the interactive setup wizard
#
# Only the wizard is translated. Every other command, and every non-interactive
# invocation, stays English. The language is per invocation and is never
# written to state.json: it is not installation state.
set -Eeuo pipefail

declare -gA GOWAVE_I18N_EN=(
    [wizard.language.prompt]="Select language / Выберите язык [en/ru]: "
    [wizard.language.invalid]="Please answer en or ru."
    [wizard.variant.prompt]="Select deployment variant:"
    [wizard.variant.trial_note]="All-in-One is recommended only for testing and familiarisation with the UI."
    [wizard.variant.option.all_in_one]="1) All-in-One — Panel, local node, Xray/REALITY/Vision on one host (trial only)"
    [wizard.variant.option.panel_only]="2) Panel-only — Panel and a static camouflage site here, plus N workers onboarded over SSH; no traffic plane on this host"
    [wizard.variant.option.multi_node]="3) All-in-One plus remote nodes — this host plus N workers onboarded over SSH"
    [wizard.variant.invalid]="Please answer 1, 2 or 3."
    [wizard.nodes.prompt]="How many remote nodes should be onboarded? "
    [wizard.nodes.invalid]="Enter a whole number of at least one."
    [wizard.name.panel]="Panel domain: "
    [wizard.name.camouflage]="Camouflage domain: "
    [wizard.name.worker]="Node %s panel domain: "
    [wizard.name.worker_camouflage]="Node %s camouflage domain: "
    [wizard.name.vision]="Vision domain (leave empty to skip): "
    [wizard.name.email]="Let's Encrypt admin email: "
    [wizard.name.invalid]="Invalid DNS hostname: %s"
    [wizard.name.empty]="A name is required here."
    [wizard.name.duplicate]="%s is already used by %s in this plan."
    [wizard.email.invalid]="Enter a valid email address."
    [wizard.yes_no.invalid]="Please answer y or n."
    [wizard.vision.prompt]="Enable Vision for %s? [y/N]: "
    [wizard.shared_domain.prompt]="Do all hosts share one registered domain? [y/N]: "
    [wizard.plan.summary]="Installation plan:"
    [wizard.plan.host]="  %s: panel=%s camouflage=%s vision=%s"
    [wizard.plan.certificates]="Certificates this plan spends: %s"
    [wizard.plan.shared]="Registered domain: shared by the whole cluster"
    [wizard.plan.separate]="Registered domain: one per host"
    [wizard.cert.separate]="Each host uses its own registered domain, so each host spends its own Let's Encrypt budget."
    [wizard.cert.shared_within]="%s certificates fit within the %s-node ceiling for this combination, but the 50-per-7-days budget is shared by the whole cluster and by anything else on that domain. Continue? [y/N]: "
    [wizard.cert.shared_refused]="Refused: %s certificates exceed the ceiling for this combination."
    [wizard.cert.ceiling]="The ceiling for this combination is %s nodes under one registered domain; use one registered domain per host."
    [wizard.cert.remaining_unknown]="The remaining Let's Encrypt budget cannot be queried."
    [wizard.dns.failed]="These names do not resolve: %s"
    [wizard.confirm]="Proceed with this plan? [y/N]: "
    [wizard.aborted]="Installation cancelled."
    [wizard.missing_tty]="Error: install with no arguments needs a terminal to run the setup wizard."
    [wizard.ssh.fingerprint]="Type the SHA-256 fingerprint of %s in full: "
    [wizard.ssh.fingerprint_mismatch]="The fingerprint does not match; refusing to authorise a key on %s."
    [wizard.ssh.scan_failed]="Could not read the SSH host key of %s."
    [wizard.ssh.cleanup_failed]="Cleanup on %s failed; the expiry timer will remove the temporary key within two hours."
    [wizard.ssh.password]="SSH password for %s: "
    [wizard.ssh.timer_failed]="Could not install the expiry timer on %s; no key was authorised."
    [wizard.ssh.cleanup]="Revoking temporary access on %s."
    [wizard.ssh.registered]="Node %s registered."
    [wizard.ssh.failed]="Node %s registration failed."
)

declare -gA GOWAVE_I18N_RU=(
    [wizard.language.prompt]="Выберите язык / Select language [ru/en]: "
    [wizard.language.invalid]="Ответьте ru или en."
    [wizard.variant.prompt]="Выберите вариант развёртывания:"
    [wizard.variant.trial_note]="All-in-One рекомендован только для тестирования и знакомства с интерфейсом."
    [wizard.variant.option.all_in_one]="1) All-in-One — Panel, локальный узел, Xray/REALITY/Vision на одном хосте (только для тестов)"
    [wizard.variant.option.panel_only]="2) Только Panel — Panel и статический сайт-прикрытие здесь, плюс N узлов, подключённых по SSH; на этом хосте трафика нет"
    [wizard.variant.option.multi_node]="3) All-in-One плюс удалённые узлы — этот хост и N узлов, подключённых по SSH"
    [wizard.variant.invalid]="Ответьте 1, 2 или 3."
    [wizard.nodes.prompt]="Сколько удалённых узлов подключить? "
    [wizard.nodes.invalid]="Введите целое число не меньше единицы."
    [wizard.name.panel]="Домен Panel: "
    [wizard.name.camouflage]="Домен прикрытия: "
    [wizard.name.worker]="Домен узла %s: "
    [wizard.name.worker_camouflage]="Домен прикрытия узла %s: "
    [wizard.name.vision]="Домен Vision (пусто — пропустить): "
    [wizard.name.email]="Email администратора Let's Encrypt: "
    [wizard.name.invalid]="Недопустимое DNS-имя: %s"
    [wizard.name.empty]="Здесь требуется имя."
    [wizard.name.duplicate]="%s уже используется в этом плане (%s)."
    [wizard.email.invalid]="Введите корректный адрес электронной почты."
    [wizard.yes_no.invalid]="Ответьте y или n."
    [wizard.vision.prompt]="Включить Vision для %s? [y/N]: "
    [wizard.shared_domain.prompt]="Все хосты используют один зарегистрированный домен? [y/N]: "
    [wizard.plan.summary]="План установки:"
    [wizard.plan.host]="  %s: panel=%s прикрытие=%s vision=%s"
    [wizard.plan.certificates]="Сертификатов по этому плану: %s"
    [wizard.plan.shared]="Зарегистрированный домен: общий для всего кластера"
    [wizard.plan.separate]="Зарегистрированный домен: свой у каждого хоста"
    [wizard.cert.separate]="У каждого хоста свой зарегистрированный домен, поэтому каждый расходует собственный бюджет Let's Encrypt."
    [wizard.cert.shared_within]="%s сертификатов укладываются в потолок %s узлов для этой комбинации, но лимит 50 сертификатов за 7 дней общий для всего кластера и для всего остального на этом домене. Продолжить? [y/N]: "
    [wizard.cert.shared_refused]="Отказ: %s сертификатов превышают потолок для этой комбинации."
    [wizard.cert.ceiling]="Потолок для этой комбинации — %s узлов на одном зарегистрированном домене; используйте отдельный домен для каждого хоста."
    [wizard.cert.remaining_unknown]="Остаток бюджета Let's Encrypt невозможно узнать."
    [wizard.dns.failed]="Эти имена не разрешаются: %s"
    [wizard.confirm]="Продолжить по этому плану? [y/N]: "
    [wizard.aborted]="Установка отменена."
    [wizard.missing_tty]="Ошибка: install без аргументов требует терминал для запуска мастера."
    [wizard.ssh.fingerprint]="Введите SHA-256 отпечаток %s полностью: "
    [wizard.ssh.fingerprint_mismatch]="Отпечаток не совпадает; ключ на %s не будет авторизован."
    [wizard.ssh.scan_failed]="Не удалось прочитать SSH-ключ хоста %s."
    [wizard.ssh.cleanup_failed]="Очистка на %s не удалась; таймер удалит временный ключ в течение двух часов."
    [wizard.ssh.password]="SSH-пароль для %s: "
    [wizard.ssh.timer_failed]="Не удалось установить таймер удаления на %s; ключ не авторизован."
    [wizard.ssh.cleanup]="Отзыв временного доступа на %s."
    [wizard.ssh.registered]="Узел %s зарегистрирован."
    [wizard.ssh.failed]="Регистрация узла %s не удалась."
)

# Accept the language as the operator typed it, and never trust an unknown value.
wizard_language_for() {
    case "${1,,}" in
        ru|ru_ru|russian|русский) printf 'ru' ;;
        en|en_us|en_gb|english|английский) printf 'en' ;;
        *) return 1 ;;
    esac
}

wizard_language() {
    local configured="${GOWAVE_WIZARD_LANG:-}"
    if wizard_language_for "$configured" >/dev/null 2>&1; then
        wizard_language_for "$configured"
    else
        printf 'en'
    fi
}

set_wizard_language() {
    local resolved
    if ! resolved=$(wizard_language_for "${1:-}"); then
        return 1
    fi
    GOWAVE_WIZARD_LANG="$resolved"
}

# Lookup with an English fallback: a missing Russian entry, or a key that only
# one catalog knows, never leaves a blank line in front of the operator.
t() {
    local key="$1"
    local value=""
    if [[ "$(wizard_language)" == "ru" ]]; then
        value="${GOWAVE_I18N_RU[$key]:-}"
    fi
    if [[ -z "$value" ]]; then
        value="${GOWAVE_I18N_EN[$key]:-$key}"
    fi
    printf '%s' "$value"
}

tf() {
    local key="$1"
    shift
    # The format string is a controlled catalog entry, never operator input.
    # shellcheck disable=SC2059
    printf "$(t "$key")" "$@"
}
