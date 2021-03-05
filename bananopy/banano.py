import requests
from collections import defaultdict

from bananopy.constants import BANANO_API
from bananopy.utils import fix_json
from bananopy.conversion import convert


class NodeException(Exception):
    """ Base class for RPC errors """


def call(action, params=None, url=None):
    params = params or {}
    params["action"] = action
    
    if url:
        response = requests.post(url, json=params)
    else:
        response = requests.post(BANANO_API, json=params)

    json_response = response.json()

    if "error" in json_response:
        raise NodeException(json_response)

    return defaultdict(str, json_response)


def account_balance(account, url=None):
    payload = {"account": account}
    r = call("account_balance", payload, url)
    return fix_json(r)


def account_block_count(account, url=None):
    payload = {"account": account}
    r = call("account_block_count", payload, url)
    return fix_json(r)


def account_get(pub_key, url=None):
    payload = {"key": pub_key}
    return call("account_get", payload, url)


def account_history(
    account, count, raw=False, head="", offset=0, reverse=False, account_filter=[], url=None
):
    payload = {
        "account": account,
        "count": count,
        "raw": raw,
        **({"head": head} if head != "" else {}),
        "offset": offset,
        "reverse": reverse,
        **({"account_filter": account_filter} if account_filter != [] else {}),
    }

    r = call("account_history", payload, url)
    r = fix_json(r)

    # hack to keep data structures consistent
    if r["history"] == {}:
        r["history"] = []

    return r


def account_info(account, representative=False, weight=False, pending=False, url=None):
    payload = {
        "account": account,
        "representative": representative,
        "weight": weight,
        "pending": pending,
    }
    r = call("account_info", payload, url)
    return fix_json(r)


def account_key(account, url=None):
    payload = {"account": account}
    return call("account_key", payload, url)


def account_representative(account, url=None):
    payload = {"account": account}
    return call("account_representative", payload, url)


def account_weight(account, url=None):
    payload = {"account": account}
    r = call("account_weight", payload, url)
    return fix_json(r)


def accounts_balances(accounts, url=None):
    payload = {"accounts": accounts}
    r = call("accounts_balances", payload, url)
    return fix_json(r)


def accounts_frontiers(accounts, url=None):
    payload = {"accounts": accounts}
    return call("accounts_frontiers", payload, url)


def accounts_pending(
    accounts,
    threshold=0,
    source=False,
    include_active=False,
    sorting=False,
    include_only_confirmed=False,
    url=None
):
    payload = {
        "accounts": accounts,
        "threshold": threshold,
        "source": source,
        "include_active": include_active,
        "sorting": sorting,
        "include_only_confirmed": include_only_confirmed,
    }
    r = call("accounts_pending", payload, url)
    return fix_json(r)


def active_difficulty(include_trend=False, url=None):
    payload = {"include_trend": include_trend}
    r = call("active_difficulty", payload, url)
    return fix_json(r)


def available_supply(url=None):
    r = call("available_supply", url=url)
    return fix_json(r)


def block_account(hash, url=None):
    payload = {"hash": hash}
    return call("block_account", payload, url)


def block_confirm(hash, url=None):
    payload = {"hash": hash}
    r = call("block_confirm", payload, url)
    return fix_json(r)


def block_count(include_cemented=True, url=None):
    payload = {"include_cemented": include_cemented}
    r = call("block_count", payload, url)
    return fix_json(r)


def block_count_type(url=None):
    r = call("block_count_type", url=url)
    return fix_json(r)


def block_create(type, balance, key, representative, link, previous, json_block=False, url=None):
    payload = {
        "type": type,
        "balance": balance,
        "key": key,
        "representative": representative,
        "link": link,
        "previous": previous,
        "json_block": json_block,
    }
    r = call("block_create", payload, url)
    return fix_json(r)


def block_hash(
    type,
    account,
    previous,
    representative,
    balance,
    link,
    link_as_account,
    signature,
    work,
    json_block=False,
    url=None
):

    payload = {
        "json_block": json_block,
        "block": {
            "type": type,
            "account": account,
            "previous": previous,
            "representative": representative,
            "balance": balance,
            "link": link,
            "link_as_account": link_as_account,
            "signature": signature,
            "work": work,
        },
    }
    return call("block_hash", payload, url)


def block_info(hash, json_block=False, url=None):
    payload = {
        "json_block": json_block,
        "hash": hash,
    }
    r = call("block_info", payload, url)
    return fix_json(r)


def blocks(hashes, json_block=False, url=None):
    payload = {
        "json_block": json_block,
        "hashes": hashes,
    }
    r = call("blocks", payload, url)
    return fix_json(r)


def blocks_info(
    hashes,
    include_not_found=False,
    pending=False,
    source=False,
    balance=False,
    json_block=False,
    url=None
):
    payload = {
        "json_block": json_block,
        "include_not_found": include_not_found,
        "hashes": hashes,
        "pending": pending,
        "source": source,
        "balance": balance,
    }
    r = call("blocks_info", payload, url)
    return fix_json(r)


def bootstrap(address, port, bypass_frontier_confirmation=False, url=None):
    payload = {
        "address": address,
        "port": port,
        "bypass_frontier_confirmation": bypass_frontier_confirmation,
    }
    return call("bootstrap", payload, url)


def bootstrap_any(force=False, url=None):
    payload = {"force": force}
    return call("bootstrap_any", payload, url)


def bootstrap_lazy(hash, force=False, url=None):
    payload = {"hash": hash, "force": force}
    return call("bootstrap_any", payload, url)


def bootstrap_status(url=None):
    r = call("bootstrap_status", url=url)
    return fix_json(r)


def chain(hash, count=-1, offset=0, reverse=False, url=None):
    payload = {
        "block": hash,
        "count": count,
        "offset": offset,
        "reverse": reverse,
    }
    return call("chain", payload, url)


def confirmation_active(announcements=0, url=None):
    payload = {"announcements": announcements}
    return call("confirmation_active", payload, url)


def confirmation_height_currently_processing(url=None):
    return call("confirmation_height_currently_processing", url=url)


def confirmation_history(hash=None, url=None):
    payload = {
        **({"hash": hash} if hash else {}),
    }
    r = call("confirmation_history", payload, url)
    return fix_json(r)


def confirmation_info(root, representatives=False, contents=False, json_block=False, url=None):
    payload = {
        "json_block": json_block,
        "root": root,
        "contents": contents,
        "representatives": representatives,
    }
    r = call("confirmation_info", payload, url)
    return fix_json(r)


def confirmation_quorum(peer_details=False, peers_stake_required=0, url=None):
    payload = {
        "peer_details": peer_details,
        "peers_stake_required": peers_stake_required,
    }
    r = call("confirmation_quorum", payload, url)
    return fix_json(r)


def database_txn_tracker(url=None):
    r = call("database_txn_tracker", url=url)
    return fix_json(r)


def delegators(account, url=None):
    payload = {"account": account}
    r = call("delegators", payload, url)
    return fix_json(r)


def delegators_count(account, url=None):
    payload = {"account": account}
    r = call("delegators_count", payload, url)
    return fix_json(r)


def deterministic_key(seed, index=0, url=None):
    payload = {"seed": seed, "index": index}
    return call("deterministic_key", payload, url)


def epoch_upgrade(epoch, key, count=None, url=None):
    payload = {
        "epoch": epoch,
        "key": key,
        **({"count": count} if count else {}),
    }
    r = call("epoch_upgrade", payload, url)
    return fix_json(r)


def frontier_count(url=None):
    r = call("frontier_count", url=url)
    return fix_json(r)


def frontiers(account, count=-1, url=None):
    payload = {"account": account, "count": count}
    return call("frontiers", payload, url)


def keepalive(address, port, url=None):
    payload = {"address": address, "port": port}
    r = call("keepalive", payload, url)
    return fix_json(r)


def key_create(url=None):
    return call("key_create", url=url)


def key_expand(key, url=None):
    payload = {"key": key}
    return call("key_expand", payload, url)


def ledger(
    account,
    count=-1,
    representative=False,
    weight=False,
    pending=False,
    modified_since=0,
    sorting=False,
    threshold=0,
    url=None
):
    payload = {
        "account": account,
        "count": count,
        "representative": representative,
        "weight": weight,
        "pending": pending,
        "modified_since": modified_since,
        "sorting": sorting,
        "threshold": threshold,
    }
    r = call("ledger", payload, url)
    return fix_json(r)


def node_id(url=None):
    return call("node_id", url=url)


def node_id_delete(url=None):
    r = call("node_id_delete", url=url)
    return fix_json(r)


# version 21.0+
# def node_telemetry():
#     return call("node_telemetry")


def peers(peer_details=False, url=None):
    payload = {"peer_details": peer_details}
    r = call("peers", payload, url)
    return fix_json(r)


def pending(
    account,
    count=-1,
    threshold=0,
    source=False,
    include_active=False,
    min_version=False,
    sorting=False,
    include_only_confirmed=True,
    url=None
):
    payload = {
        "account": account,
        "count": count,
        "threshold": threshold,
        "source": source,
        "include_active": include_active,
        "min_version": min_version,
        "sorting": sorting,
        "include_only_confirmed": include_only_confirmed,
    }
    r = call("pending", payload, url)
    return fix_json(r)


def pending_exists(hash, include_active=False, include_only_confirmed=False, url=None):
    payload = {
        "hash": hash,
        "include_active": include_active,
        "include_only_confirmed": include_only_confirmed,
    }
    r = call("pending_exists", payload, url)
    return fix_json(r)


def process(
    block_type,
    account,
    previous,
    representative,
    balance,
    link,
    link_as_account,
    signature,
    work,
    json_block=False,
    subtype="",
    force=False,
    watch_work=True,
    url=None
):
    payload = {
        "json_block": json_block,
        "subtype": subtype,
        "watch_work": watch_work,
        "block": {
            "type": block_type,
            "account": account,
            "previous": previous,
            "representative": representative,
            "balance": balance,
            "link": link,
            "link_as_account": link_as_account,
            "signature": signature,
            "work": work,
        },
        "force": force,
    }
    return call("process", payload, url)


def representatives(count=-1, sorting=False, url=None):
    payload = {"count": count, "sorting": sorting}
    r = call("representatives", payload, url)
    return fix_json(r)


def representatives_online(weight=False, url=None):
    payload = {"weight": weight}
    r = call("representatives_online", payload, url)
    return fix_json(r)


def republish(hash, sources=False, destinations=False, url=None):
    payload = {
        "hash": hash,
        "sources": sources,
        "destinations": destinations,
    }
    return call("republish", payload, url)


def sign(
    block_type=None,
    previous_block=None,
    representative=None,
    balance=None,
    link=None,
    link_as_account=None,
    signature=None,
    work=None,
    hash=None,
    key=None,
    wallet=None,
    account=None,
    json_block=False,
    url=None
):
    # distinguish between hash sign and block sign
    payload = (
        {"hash": hash}
        if hash is not None
        else {
            "json_block": json_block,
            **({"key": key} if key else {}),
            **({"wallet": wallet} if wallet else {}),
            **({"account": account} if account else {}),
            "block": {
                "type": block_type,
                "account": account,
                "previous": previous_block,
                "representative": representative,
                "balance": balance,
                "link": link,
                "link_as_account": link_as_account,
                "signature": signature,
                "work": work,
            },
        }
    )
    r = call("sign", payload, url)
    return fix_json(r)


def stats(stats_type, url=None):
    payload = {"type": stats_type}
    r = call("stats", payload, url)
    return fix_json(r)


def stats_clear(url=None):
    return call("stats_clear", url=url)


def stop(url=None):
    return call("stop", url=url)


def successors(hash, count=-1, offset=0, reverse=False, url=None):
    payload = {
        "block": hash,
        "count": count,
        "offset": offset,
        "reverse": reverse,
    }
    return call("successors", payload, url)


def validate_account_number(account, url=None):
    payload = {"account": account}
    r = call("validate_account_number", payload, url)
    return fix_json(r)


def version(url=None):
    r = call("version", url=url)
    return fix_json(r)


def unchecked(count=-1, json_block=False, url=None):
    payload = {"count": count, "json_block": json_block}
    r = call("unchecked", payload, url)
    return fix_json(r)


def unchecked_clear(url=None):
    r = call("unchecked_clear", url=url)
    return fix_json(r)


def unchecked_get(hash, json_block=False, url=None):
    payload = {"hash": hash, "json_block": json_block}
    r = call("unchecked_get", payload, url)
    return fix_json(r)


def unchecked_keys(key, count=-1, json_block=False, url=None):
    payload = {
        "key": key,
        "count": count,
        "json_block": json_block,
    }
    r = call("unchecked_keys", payload, url)
    return fix_json(r)


def unopened(account, count=-1, threshold=0, url=None):
    payload = {
        "account": account,
        "count": count,
        "threshold": threshold,
    }
    r = call("unopened", payload, url)
    return fix_json(r)


def uptime(url=None):
    r = call("uptime", url=url)
    return fix_json(r)


def work_cancel(hash, url=None):
    payload = {"hash": hash}
    return call("work_cancel", payload, url)


def work_generate(
    hash, use_peers=False, difficulty=None, multiplier=None, account=None, url=None
):
    payload = {
        "hash": hash,
        "use_peers": use_peers,
        **({"difficulty": difficulty} if difficulty else {}),
        **({"multiplier": multiplier} if multiplier else {}),
        **({"account": difficulty} if account else {}),
    }
    return call("work_generate", payload, url)


def work_peer_add(address, port, url=None):
    payload = {"address": address, "port": port}
    r = call("work_peer_add", payload, url)
    return fix_json(r)


def work_peers(url=None):
    return call("work_peers", url=url)


def work_peers_clear(url=None):
    r = call("work_peers_clear", url=url)
    return fix_json(r)


def work_validate(work, hash, difficulty=None, multiplier=None, url=None):
    payload = {
        "hash": hash,
        **({"difficulty": difficulty} if difficulty else {}),
        **({"multiplier": multiplier} if multiplier else {}),
    }
    return call("work_validate", payload, url)


def account_create(wallet, index=None, work=True, url=None):
    # FIXME: use Decimals for multiplier
    payload = {
        "wallet": wallet,
        "work": work,
        **({"index": index} if index else {}),
    }
    return call("account_create", payload, url)


def account_list(wallet, url=None):
    payload = {"wallet": wallet}
    return call("account_list", payload, url)


def account_move(wallet, source, accounts, url=None):
    payload = {
        "wallet": wallet,
        "source": source,
        "accounts": accounts,
    }
    r = call("account_move", payload, url)
    return fix_json(r)


def account_remove(wallet, account, url=None):
    payload = {"wallet": wallet, "account": account}
    r = call("account_remove", payload, url)
    return fix_json(r)


def account_representative_set(wallet, account, representative, work=None, url=None):
    payload = {
        "wallet": wallet,
        "account": account,
        "representative": representative,
        **({"work": work} if work else {}),
    }
    return call("account_representative_set", payload, url)


def accounts_create(wallet, count, work=True, url=None):
    payload = {
        "wallet": wallet,
        "count": count,
        "work": work,
    }
    return call("accounts_create", payload, url)


def password_change(wallet, password, url=None):
    payload = {"wallet": wallet, "password": password}
    r = call("password_change", payload, url)
    return fix_json(r)


def password_enter(wallet, password, url=None):
    payload = {"wallet": wallet, "password": password}
    r = call("password_enter", payload, url)
    return fix_json(r)


def password_valid(wallet, url=None):
    payload = {"wallet": wallet}
    r = call("password_valid", payload, url)
    return fix_json(r)


def receive(wallet, account, block, work=None, url=None):
    payload = {
        "wallet": wallet,
        "account": account,
        "block": block,
        **({"work": work} if work else {}),
    }
    return call("receive", payload, url)


def receive_minimum(url=None):
    r = call("receive_minimum", url=url)
    return fix_json(r)


def receive_minimum_set(amount, url=None):
    payload = {"amount": amount}
    r = call("receive_minimum_set", payload, url)
    return fix_json(r)


def search_pending(wallet, url=None):
    payload = {"wallet": wallet}
    r = call("search_pending", payload, url)
    return fix_json(r)


def search_pending_all(url=None):
    r = call("search_pending_all", url=url)
    return fix_json(r)


def send(wallet, source, destination, amount, id=None, work=None, url=None):
    payload = {
        "wallet": wallet,
        "source": source,
        "destination": destination,
        "amount": amount,
        **({"id": id} if id else {}),
        **({"work": work} if work else {}),
    }
    return call("send", payload, url)


def wallet_add(wallet, key, work=False, url=None):
    payload = {"wallet": wallet, "key": key, "work": work}
    return call("wallet_add", payload, url)


def wallet_add_watch(wallet, accounts, url=None):
    payload = {"wallet": wallet, "accounts": accounts}
    r = call("wallet_add_watch", payload, url)
    return fix_json(r)


def wallet_balances(wallet, threshold=None, url=None):
    payload = {
        "wallet": wallet,
        **({"threshold": threshold} if threshold else {}),
    }
    r = call("wallet_balances", payload, url)
    return fix_json(r)


def wallet_change_seed(wallet, seed, count=0, url=None):
    payload = {
        "wallet": wallet,
        "seed": seed,
        "count": count,
    }
    r = call("wallet_change_seed", payload, url)
    return fix_json(r)


def wallet_contains(wallet, account, url=None):
    payload = {"wallet": wallet, "account": account}
    r = call("wallet_contains", payload, url)
    return fix_json(r)


def wallet_create(seed=None, url=None):
    payload = {
        **({"seed": seed} if seed else {}),
    }
    return call("wallet_create", payload, url)


def wallet_destroy(wallet, url=None):
    payload = {"wallet": wallet}
    r = call("wallet_destroy", payload, url)
    return fix_json(r)


def wallet_export(wallet, url=None):
    payload = {"wallet": wallet}
    r = call("wallet_export", payload, url)
    return fix_json(r)


def wallet_frontiers(wallet, url=None):
    payload = {"wallet": wallet}
    return call("wallet_frontiers", payload, url)


def wallet_history(wallet, modified_since=0, url=None):
    payload = {
        "wallet": wallet,
        "modified_since": modified_since,
    }
    r = call("wallet_history", payload, url)
    return fix_json(r)


def wallet_info(wallet, url=None):
    payload = {"wallet": wallet}
    r = call("wallet_info", payload, url)
    return fix_json(r)


def wallet_ledger(
    wallet, representative=False, weight=False, pending=False, modified_since=0, url=None
):
    payload = {
        "wallet": wallet,
        "representative": representative,
        "weight": weight,
        "pending": pending,
        "modified_since": modified_since,
    }
    r = call("wallet_ledger", payload, url)
    return fix_json(r)


def wallet_lock(wallet, url=None):
    payload = {"wallet": wallet}
    r = call("wallet_lock", payload, url)
    return fix_json(r)


def wallet_locked(wallet, url=None):
    payload = {"wallet": wallet}
    r = call("wallet_locked", payload, url)
    return fix_json(r)


def wallet_pending(
    wallet,
    count=-1,
    threshold=None,
    source=False,
    include_active=False,
    min_version=False,
    include_only_confirmed=False,
    url=None
):
    payload = {
        "wallet": wallet,
        "count": count,
        **({"threshold": threshold} if threshold else {}),
        "source": source,
        "include_active": include_active,
        "min_version": min_version,
        "include_only_confirmed": include_only_confirmed,
    }
    r = call("wallet_pending", payload, url)
    return fix_json(r)


def wallet_representative(wallet, url=None):
    payload = {"wallet": wallet}
    return call("wallet_representative", payload, url)


def wallet_representative_set(wallet, representative, update_existing_accounts=False, url=None):
    payload = {
        "wallet": wallet,
        "representative": representative,
        "update_existing_accounts": update_existing_accounts,
    }
    r = call("wallet_representative_set", payload, url)
    return fix_json(r)


def wallet_republish(wallet, count=-1, url=None):
    payload = {"wallet": wallet, "count": count}
    return call("wallet_history", payload, url)


def wallet_work_get(wallet, url=None):
    payload = {"wallet": wallet}
    return call("wallet_work_get", payload, url)


def work_get(wallet, account, url=None):
    payload = {"wallet": wallet, "account": account}
    return call("work_get", payload, url)


def work_set(wallet, account, work, url=None):
    payload = {"wallet": wallet, "account": account, "work": work}
    r = call("work_set", payload, url)
    return fix_json(r)


# shortcuts
def ban_from_raw(amount):
    return convert(amount, "raw", "ban")


def ban_to_raw(amount):
    return convert(amount, "ban", "raw")


def ban_to_banoshi(amount):
    return convert(amount, "ban", "banoshi")


def ban_from_banoshi(amount):
    return convert(amount, "banoshi", "ban")
