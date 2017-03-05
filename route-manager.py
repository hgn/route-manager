#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import aiohttp.web
import time
import sys
import os
import json
import datetime
import argparse
import pprint
import subprocess
import urllib.request

class DSCP:
    IPTOS_LOWDELAY = 0x10
    IPTOS_THROUGHPUT = 0x08
    IPTOS_RELIABILITY = 0x04
    IPTOS_LOWCOST = 0x02
    IPTOS_MINCOST = 0x02

    # RFC2474
    AF11 = 0x28
    AF12 = 0x30
    AF13 = 0x38
    AF21 = 0x48
    AF22 = 0x50
    AF23 = 0x58
    AF31 = 0x68
    AF32 = 0x70
    AF33 = 0x78
    AF41 = 0x88
    AF42 = 0x90
    AF43 = 0x98

    CS0 = 0x00
    CS1 = 0x20
    CS2 = 0x40
    CS3 = 0x60
    CS4 = 0x80
    CS5 = 0xa0
    CS6 = 0xc0
    CS7 = 0xe0

    EF = 0xb8



# default false, can be changed via program arguments (-v)
DEBUG_ON = False

# exit codes for shell, failre cones can be sub-devided
# if required and shell/user has benefit of this information
EXIT_OK      = 0
EXIT_FAILURE = 1

def time_fnt():
    return datetime.datetime.now().strftime('%H:%M:%S')

def err(msg):
    sys.stderr.write(msg)
    sys.exit(EXIT_FAILURE)

def warn(msg):
    sys.stderr.write(msg)


def debug(msg):
    if not DEBUG_ON: return
    sys.stderr.write(msg)


def debugpp(d):
    if not DEBUG_ON: return
    pprint.pprint(d, indent=2, width=200, depth=6)
    sys.stderr.write("\n")


def msg(msg):
    sys.stdout.write(msg)


def execute_command(command):
    print(command)
    return subprocess.check_output(command.split(), shell=True).decode("utf-8")


def terminal_local_rest_create_inbound_routes(ctx, next_hop):
    if not "networks-local" in ctx["conf"]:
        return list() # empty list
    routes = list()
    for network in ctx["conf"]["networks-local"]:
        if network["proto"] != "v4":
            raise Exception("Network protocol not supported")
        # { "prefix": "192.168.1.0": "prefixlen": "24", "gateway": "1.1.1.1", "interface": "eth0" },
        entry = dict()
        entry["prefix"] = network["prefix"]
        entry["prefixlen"] = network["prefix-len"]
        entry["interface"] = "eth0"
        entry["gateway"] = next_hop
        routes.append(entry)
    return routes


def terminal_local_rest_process(ctx, interface):
    url = interface["type-data"]["url-set-routes"]
    addr_v4 = interface["terminal-ipv4"]
    terminal_inbound_routes = terminal_local_rest_create_inbound_routes(ctx, addr_v4)
    fwd_terminal_local_rest(url, terminal_inbound_routes)


def inform_periodically_terminal_local_rest(ctx, interface):
    terminal_local_rest_process(ctx, interface)


def inform_periodically(ctx):
    print("periodic inform handler")
    for interface in ctx["conf"]["interfaces"]:
        if interface["type"] == "terminal-local-rest":
            inform_periodically_terminal_local_rest(ctx, interface)
            continue
        raise Exception("terminal type not supported")


async def route_broadcast(ctx):
    interval = 5
    while True:
        try:
            await asyncio.sleep(interval)
            inform_periodically(ctx)
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()


async def print_routes_periodically(ctx):
    interval = 5
    while True:
        try:
            await asyncio.sleep(interval)
            #print_routes(ctx)
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()


def db_check_outdated_underlay(ctx):
    timeout = ctx['conf']['common']['underlay-deadtime']
    if not ctx['db-underlay-last-updated']:
        return
    diff = datetime.datetime.utcnow() - ctx['db-underlay-last-updated']
    if diff > float(timeout):
        # reset everything
        print("underlay older than {}, remove it now".format(timeout))
        ctx['db-underlay'] = dict()


def db_check_outdated_overlay(ctx):
    timeout = ctx['conf']['common']['overlay-deadtime']
    if not ctx['db-overlay-last-updated']:
        return
    diff = datetime.datetime.utcnow() - ctx['db-overlay-last-updated']
    if diff > float(timeout):
        # reset everything
        print("overlay older than {}, remove it now".format(timeout))
        ctx['db-overlay'] = dict()


def db_check_outdated(ctx):
    db_check_outdated_underlay(ctx)
    db_check_outdated_overlay(ctx)


async def db_check_outdated_periodically(ctx):
    # normally overlay as well as underlay send us
    # the full set of routes, but it can happen that
    # the overlay or underlay process died, yes. We should
    # delete the routes too, right? This is save default,
    # to catch any errors and bring the system in a stable
    # state again. If everything is fine we can probably remove
    # this functionality in the future.
    interval = 5
    while True:
        try:
            await asyncio.sleep(interval)
            db_check_outdated(ctx)
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()



def fwd_terminal_local_rest(url, data):
    proxy_support = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_support)
    urllib.request.install_opener(opener)
    req = urllib.request.Request(url)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('User-Agent', 'Mozilla/1.22 (compatible; MSIE 2.0; Windows 95),')
    tx_data = json.dumps(data).encode('utf-8')
    print("TX data to: \"{}\"".format(url))
    print(tx_data)
    try:
        with urllib.request.urlopen(req, tx_data, timeout=3) as res:
            resp = json.loads(str(res.read(), "utf-8"))
            print(pprint.pformat(resp))
    except urllib.error.URLError as e:
        print("Connection error: {}".format(e))


def process_overlay_full_dynamic(ctx, data):
    warn("receive message from OVERERLAY (DMPRD)\n")
    if not 'route-tables' in data:
        warn("message seems corrupt, no route-tables in data\n")
        return False
    tables = data['route-tables']
    print("\n")
    for table_name, table_list in tables.items():
        print("{}  table: {}".format(time_fnt(), table_name))
        for table_item in table_list:
            # {'prefix-len': '24', 'proto': 'v4', 'prefix': '44.101.177.0',
            # 'interface': 'wifi0', 'next-hop': '10.10.10.140'}
            ipfull = "{}/{}".format(table_item['prefix'], table_item['prefix-len'])
            iface = table_item['interface']
            next_hop = table_item['next-hop']
            info = "{} via {} at {}".format(ipfull, next_hop, iface)
            print("  {}".format(info))
    return True


async def overlay_handle_rest_rx(request):
    ctx = request.app['ctx']
    # usually from DMPRD
    try:
        request_data = await request.json()
        ok = process_overlay_full_dynamic(ctx, request_data)
    except json.decoder.JSONDecodeError:
        response_data = {'status': 'failure', "message": "data not properly formated"}
        body = json.dumps(response_data).encode('utf-8')
        return aiohttp.web.Response(body=body, content_type="application/json")
    status = 'ok'
    if not ok:
        status = 'fail'
    response_data = {'status': status, "data" : None}
    body = json.dumps(response_data).encode('utf-8')
    return aiohttp.web.Response(body=body, content_type="application/json")


def process_underlay_full_dynamic(ctx, data):
    warn("receive message from UNDERLAY (ohndl)\n")
    pprint.pprint(data)
    print("\n")
    return True


async def underlay_handle_rest_rx(request):
    ctx = request.app['ctx']
    # usually from OHNDL
    try:
        request_data = await request.json()
        ok = process_underlay_full_dynamic(ctx, request_data)
    except json.decoder.JSONDecodeError:
        response_data = {'status': 'failure', "message": "data not properly formated"}
        body = json.dumps(response_data).encode('utf-8')
        return aiohttp.web.Response(body=body, content_type="application/json")
    status = 'ok'
    ctx['db-underlay-last-updated'] = datetime.datetime.utcnow()
    if not ok:
        status = 'fail'
    response_data = {'status': status, "data" : None}
    body = json.dumps(response_data).encode('utf-8')
    return aiohttp.web.Response(body=body, content_type="application/json")


def http_init(ctx, loop):
    app = aiohttp.web.Application(loop=loop)
    app['ctx'] = ctx
    overlay_path = ctx['conf']['dynamic-receiver']['overlay']['path']
    app.router.add_route('POST', overlay_path, overlay_handle_rest_rx)
    underlay_path = ctx['conf']['dynamic-receiver']['underlay']['path']
    app.router.add_route('POST', underlay_path, underlay_handle_rest_rx)
    server = loop.create_server(app.make_handler(),
                                conf['common']['v4_listen_addr'],
                                conf['common']['v4_listen_port'])
    fmt = "HTTP IPC server started at http://{}:{}\n"
    msg(fmt.format(conf['common']['v4_listen_addr'], conf['common']['v4_listen_port']))
    loop.run_until_complete(server)


def ctx_new(conf):
    ctx = dict()
    ctx['conf'] = conf
    ctx['db-underlay'] = dict()
    ctx['db-underlay-last-updated'] = None
    ctx['db-overlay'] = dict()
    ctx['db-overlay-last-updated'] = None
    return ctx


def main(conf):
    ctx = ctx_new(conf)
    loop = asyncio.get_event_loop()
    http_init(ctx, loop)
    #asyncio.ensure_future(route_broadcast(ctx))
    asyncio.ensure_future(print_routes_periodically(ctx))
    asyncio.ensure_future(db_check_outdated_periodically(ctx))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        for task in asyncio.Task.all_tasks():
            task.cancel()
        loop.close()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--configuration", help="configuration", type=str, default=None)
    parser.add_argument("-v", "--verbose", help="verbose", action='store_true', default=False)
    args = parser.parse_args()
    if not args.configuration:
        err("Configuration required, please specify a valid file path, exiting now\n")
    return args


def load_configuration_file(args):
    with open(args.configuration) as json_data:
        return json.load(json_data)


def init_global_behavior(args, conf):
    global DEBUG_ON
    if conf['common']['debug'] or args.verbose:
        msg("Debug: enabled\n")
        DEBUG_ON = True
    else:
        msg("Debug: disabled\n")


def check_system_table_conf(tables):
    system_tables = set()
    with open("/etc/iproute2/rt_tables", "r") as fd:
        for line in fd.readlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            elements = line.split()
            if len(elements) != 2:
                continue
            system_tables.add(elements[1])
    for name in tables:
        if name not in system_tables:
            err("routing table: {}, not in system table: {}\n".format(
                name, "/etc/iproute2/rt_tables"))


def check_conf_tables(conf):
    table_set = set()
    if not "default-table" in conf:
        err("No default table configured\n")
    def_table = conf["default-table"]
    found_default_table = False
    for selectors in conf['table-selectors']:
        table_set.add(selectors['table'])
        if def_table == selectors['table']:
            found_default_table = True
    if not found_default_table:
        err("default table must be in table selector list as well")
    check_system_table_conf(table_set)


def check_interfaces(conf):
    if not "interfaces" in conf:
        err("No interfaces configured\n")
    for interface in conf['interfaces']:
        if not 'type' in interface:
            err("No type for interface configured\n")
        type_ = interface['type']
        if type_ not in ('terminal-local-rest'):
            err("interface not supported: {}".format(type_))
        if not 'type-data' in interface:
            err("No type-data for interface configured\n")


def check_conf(conf):
    check_conf_tables(conf)
    check_interfaces(conf)


def conf_init():
    args = parse_args()
    conf = load_configuration_file(args)
    init_global_behavior(args, conf)
    check_conf(conf)
    return conf


if __name__ == '__main__':
    msg("Router Manager, 2017\n")
    conf = conf_init()
    main(conf)
