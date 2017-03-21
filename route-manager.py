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
import logging

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


log = logging.getLogger()


# default false, can be changed via program arguments (-v)
DEBUG_ON = False

# exit codes for shell, failre cones can be sub-devided
# if required and shell/user has benefit of this information
EXIT_OK      = 0
EXIT_FAILURE = 1

# NFT default table manager for route manager
NFT_TABLE_NAME = "route_manager"



class RouteEntry(object):

    def __init__(self, prefix, prefix_len, next_hop,
                interface, l1_next_hop_v4=None, l1_iface_name=None, proto="v4",
                table=None, origin=None, origin_iface=None):
        self._my_attribute = 0
        self.update_mtime()
        self._prefix = prefix
        self._prefix_len = prefix_len
        self._next_hop = next_hop
        self._interface = interface
        self._l1_next_hop_v4 = l1_next_hop_v4
        self._l1_iface_name = l1_iface_name
        self._proto = proto
        self._table = table
        self._origin = origin
        self._origin_iface = origin_iface
        self._state = "undefined"


    def __str__(self):
        delta = datetime.datetime.utcnow() - self._mtime
        s  = "[state:{>:5}]".format(self._state)
        s  = " {>15}/{:2}".format(self._prefix, self._prefix_len)
        s += " via {:16} dev {:6}".format(self._next_hop, self._interface)
        s += " proto:{:2}".format(self._proto)
        s += " mtime:{:.2f}".format(delta.total_seconds())
        s += " table:{:10}".format(self._table)
        s += "  ["
        s += "l1-next-v4:{}".format(self._l1_next_hop_v4)
        s += ",l1-next-iface:{}".format(self._l1_iface_name)
        s += ",origin:{}".format(self._origin)
        s += ",origin-iface:{}".format(self._origin_iface)
        s += "]"
        return s


    def update_mtime(self):
        self._mtime = datetime.datetime.utcnow()


    def cmp_base(self, other):
        if self._proto != other._proto:
            return False
        if self._prefix != other._prefix:
            return False
        if self._prefix_len != other._prefix_len:
            return False
        return True


    def __eq__(self, other):
        if not self.cmp_base(other):
            return False
        if self._next_hop != other._next_hop:
            return False
        if self._table != other._table:
            return False
        if self._l1_next_hop_v4 != other._l1_next_hop_v4:
            return False
        if self._l1_iface_name != other._l1_iface_name:
            return False
        if self._origin != other._origin:
            return False
        if self._origin_iface != other._origin_iface:
            return False
        return True


    def cmp_next_hop(self, other):
        if self._next_hop == other._next_hop:
            return True
        return False

    @property
    def next_hop(self):
        return self._next_hop


    @next_hop.setter
    def next_hop(self, value):
        self._next_hop = value

    @property
    def origin(self):
        return self._origin


    @property
    def origin_iface(self):
        return self._origin_iface


    @property
    def interface(self):
        return self._interface


    @interface.setter
    def interface(self, value):
        self._interface = value


    @property
    def mtime(self):
        return self._mtime


    @property
    def prefix(self):
        return self._prefix

    @property
    def prefix_len(self):
        return self._prefix_len


    @property
    def l1_next_hop_v4(self):
        return self._l1_next_hop_v4


    @l1_next_hop_v4.setter
    def l1_next_hop_v4(self, value):
        self._l1_next_hop_v4 = value

    @property
    def l1_iface_name(self):
        return self._l1_iface_name


    @l1_iface_name.setter
    def l1_iface_name(self, value):
        self._l1_iface_name = value


    @property
    def state(self):
        return self._state


    @state.setter
    def state(self, value):
        if value not in ("undefined", "new", "old"):
            raise Exception("state not allowed {}".format(value))
        self._state = value



class RouteDB(object):

    def __init__(self, timeout=60):
        self.db = list()
        self._timeout = timeout


    def update(self, entry):
        """ this will add the route entry if not available
            and return true if it is a new element, false if not
            If the entry is already in the database it will check if
            the next-hop is identical, not not it will overwrite and
            return True, if it is identical in all belongs it will just
            update the mtime timestamp and return False"""
        for old_entry in self.db:
            if not old_entry.cmp_base(entry):
                continue
            # ok, identical in base, in whole?
            if old_entry == entry:
                print("route entry full identical")
                old_entry.update_mtime()
                return False
            # ok, prefix differes
            print("route prefix identical, next/interface differs")
            old_entry.next_hop = entry.next_hop
            old_entry.interface = entry.interface
            old_entry.update_mtime()
            old.state = "new" # to signal that this entry is new
            return True
        # ok, new element
        print("new  entry added to db")
        entry.update_mtime()
        entry.state = "new" # to signal that this entry is new
        self.db.append(entry)
        return True


    def gc(self):
        now = datetime.datetime.utcnow()
        for entry in self.db[:]:
            if entry.origin == "config":
                # static configured routes are never
                # removed
                continue
            diff = now - entry.mtime
            if diff.total_seconds() > float(self._timeout):
                print("remove outdated routing entry")
                self.db.remove(entry)

    def renew(self):
        for entry in self.db:
            entry.state == "new"


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


def execute_command(command, suppress_output=False):
    print("  execute \"{}\"".format(command))
    p = subprocess.Popen(command.split(), stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=False)
    out, err = p.communicate()
    if not suppress_output:
        lines = err.decode("utf-8")
        for line in lines.splitlines():
            sys.stderr.write("    {}\n".format(line))
        sys.stderr.write(err.decode("utf-8"))
        lines = out.decode("utf-8")
        for line in lines.splitlines():
            sys.stderr.write("    {}\n".format(line))
    p.wait()


def rest_url_by_interface(ctx, iface_name):
    interfaces = ctx['conf']['interfaces']
    for interface in interfaces:
        if interface['name'] != iface_name:
            continue
        return interface['type-data']['url-routes-set']
    raise Exception("interface not specided for term {}".format(iface_name))


def set_ip_routes(ctx, iface_name, routes):
    url = rest_url_by_interface(ctx, iface_name)
    user_agent_headers = { 'Content-type': 'application/json',
                           'Accept':       'application/json' }
    proxy_support = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_support)
    urllib.request.install_opener(opener)

    data = dict()
    data['routes'] = list()

    for route in routes:
        r = dict()
        r['iface'] = route['iface']
        r['prefix'] = route['prefix']
        r['next-hop'] = route['next-hop']
        data['routes'].append(r)

    tx_data = json.dumps(data).encode('utf-8')
    print("Query: {}".format(url))
    request = urllib.request.Request(url, tx_data, user_agent_headers)
    try:
        server_response = urllib.request.urlopen(request).read()
    except urllib.error.HTTPError as e:
        print("Failed to reach the route-manager ({}): '{}'".format(url, e.reason))
        return None
    except urllib.error.URLError as e:
        print("Failed to reach the route-manager ({}): '{}'".format(url, e.reason))
        return None
    server_data = json.loads(str(server_response, "utf-8"))
    print("Answer IPC:")
    print(server_data)
    return server_data


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
    for route_entry in ctx["route-db"].db:
        print(route_entry)


async def route_broadcast(ctx):
    interval = 5
    while True:
        try:
            await asyncio.sleep(interval)
            inform_periodically(ctx)
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()


def print_routes_underlay(ctx):
    print("Underlay routes:")
    for interface_name, interface_data in ctx['db-underlay'].items():
        for l0_top_addr_v4, route in interface_data.items():
            print("neighbor {} - data: {}".format(l0_top_addr_v4, route))


def print_routes_overlay(ctx):
    print("Overlay routes:")
    for route in ctx['db-overlay']:
        ipfull   = "{}/{}".format(route['prefix'], route['prefix-len'])
        iface    = route['interface']
        next_hop = route['next-hop']
        tbl_name = route['table-name']
        info = "{:>15} via {:15} dev {:5} [{}]".format(ipfull, next_hop, iface, tbl_name)
        print(info)


def print_routes(ctx):
    if ctx['args'].cinema: print("\033c")
    print_routes_underlay(ctx)
    print_routes_overlay(ctx)


async def route_db_gc(ctx):
    interval = 10
    while True:
        try:
            await asyncio.sleep(interval)
            ctx["route-db"].gc()
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()


async def route_renew(ctx):
    # every interval seconds we set the state to new to enforce
    # a reseting of the routing tables. It is better routes are
    # configured several time compared where a route was not set
    interval = 120
    while True:
        try:
            await asyncio.sleep(interval)
            ctx["route-db"].renew()
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()


async def print_routes_periodically(ctx):
    interval = 10
    if ctx['args'].cinema:
        interval = .5
    while True:
        try:
            await asyncio.sleep(interval)
            print_routes(ctx)
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()


def route_configure_local(ctx, route):
    pass


def route_configure_remote_rest(ctx, iface_name, iface_data, route):
    url = iface_data["type-data"]["url-set-routes"]
    assert(False)


def route_configure_remote(ctx, iface_name, iface_data, route):
    if iface_data["type"] == "terminal-local-rest":
        route_configure_remote_rest(ctx, iface_name, iface_data, route)
    else:
        assert(False)


def route_configure_remote(ctx, iface, route):
    for iface_data in ctx["conf"]["interfaces"]:
        if iface_data["name"] != iface_name:
            continue
        return route_configure_remote(ctx, ifaace_name, iface_data, route)
    assert(False)


def db_check_outdated_underlay(ctx):
    timeout = ctx['conf']['common']['underlay-deadtime']
    if not ctx['db-underlay-last-updated']:
        return
    diff = datetime.datetime.utcnow() - ctx['db-underlay-last-updated']
    if diff.total_seconds() > float(timeout):
        # reset everything
        print("underlay older than {}, remove it now".format(timeout))
        ctx['db-underlay'] = dict()
        ctx['db-underlay-last-updated'] = None


def db_check_outdated_overlay(ctx):
    timeout = ctx['conf']['common']['overlay-deadtime']
    if not ctx['db-overlay-last-updated']:
        return
    diff = datetime.datetime.utcnow() - ctx['db-overlay-last-updated']
    if diff.total_seconds() > float(timeout):
        # reset everything
        print("overlay older than {}, remove it now".format(timeout))
        ctx['db-overlay'] = list()
        ctx['db-overlay-last-updated'] = None


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
        pass

def overlay_purge(ctx):
    # remove old entry because DMPR will always send
    # us the complete routes
    ctx['db-overlay'] = list()


def overlay_add_new(ctx, tables):
    # return true when the data was valid in some
    # ways, just to inform the caller if the syntax
    # is not correct, corrupt, ...
    for route_entry in tables:
        keys = ("prefix", "prefix-len", 'interface', 'next-hop', 'table-name')
        if not all (k in route_entry for k in keys):
            log.error("packet from DMPR corrupt: {}".format(route_entry))
            return False
        ctx['db-overlay'].append(route_entry)
        ctx['db-overlay-last-updated'] = datetime.datetime.utcnow()
    return True


def execute_route_flush_v4(ctx, table=None):
    cmd = "ip -4 route flush table {}".format(table)
    execute_command(cmd)


def execute_route_flush_v6(ctx, table=None):
    cmd = "ip -6 route flush table {}".format(table)
    execute_command(cmd)


def execute_route_add(ctx, prefix, prefix_len, next_hop, interface, table=None):
    full_prefix = "{}/{}".format(prefix, prefix_len)
    cmd = "ip route add {} via {} dev {}".format(full_prefix, next_hop, interface)
    if table:
        cmd += " table {}".format(table)
    execute_command(cmd)


def execute_route_show(ctx, tables):
    for table in tables:
        cmd = "ip route show table {}".format(table)
        execute_command(cmd)


def overlay_routing_tables_calc(ctx):
    tables = set()
    for entry in ctx['db-overlay']:
        tables.add(entry['table-name'])
    return tables

def process_overlay_terminal_local(ctx, entry):
    prefix     = entry['prefix']
    prefix_len = entry['prefix-len']
    interface  = entry['interface']
    next_hop   = entry['next-hop']
    table_name = entry['table-name']
    execute_route_add(ctx, prefix, prefix_len, next_hop,
                          interface, table=table_name)
    # add default route too
    execute_route_add(ctx, prefix, prefix_len, next_hop, interface)
    execute_route_show(ctx, affected_tables)


def process_overlay_terminal_rest(ctx, entry):
    pass


def process_overlay_terminal_local_rest(ctx, entry):
    process_overlay_terminal_local(ctx, entry)
    process_overlay_terminal_rest(ctx, entry)



def process_overlay_gre(ctx, entry):
    # see process_overlay_terminal_local_rest()
    pass


def route_flush_terminal_local_rest(ctx):
    for iface_data in ctx['conf']['interface']:
        name = iface_data['name']
        route_flush_configured_rt_tables(ctx, iface_name=name)


def route_local_update_overlay_routes(ctx):
    #log.debug("update local routes")
    route_flush_terminal_local_rest(ctx)
    for entry in ctx['db-overlay']:
        iface_name = entry['interface']
        for iface_data in ctx['conf']['interfaces']:
            if iface_data['name'] != iface_name:
                continue
            if iface_data['type'] == 'terminal-local-rest':
                return process_overlay_terminal_local_rest(ctx, data)
            elif iface_data['type'] == 'gre':
                return process_overlay_gre(ctx, data)
        raise Exception("interface type not specided")


def query_l1_addr_by_pl_iface(ctx, iface_name):
    if not iface_name in ctx["l1-map"]:
        return None
    return ctx["l1-map"][iface_name]


def overlay_route_local_update_routes(ctx, entry):
    # shared between l0 & l1
    prefix      = entry['prefix']
    prefix_len  = entry['prefix-len']

    # l0
    interface   = entry['interface']

    # the next hop is the pl_l0_bottom_addr_v4, not the ip
    # address in the packet, because this is the other platform
    # ip address
    if not interface in ctx['db-underlay']:
        return
    next_hop    = ctx['db-underlay'][interface]['terminal-data']['pl_l0_bottom_addr_v4']
    table_name  = entry['table-name']

    # l1
    l1_next_hop    = query_l1_addr_by_pl_iface(ctx, interface)
    if not interface in ctx["db-underlay"]:
        #no data yet, wait until data is available
        return False
    l1_iface_name  = ctx['db-underlay'][interface]['terminal-data']['pl_l1_top_iface_name']

    e = RouteEntry(prefix, prefix_len, next_hop, interface,
                   l1_next_hop_v4=l1_next_hop, l1_iface_name=l1_iface_name,
                   proto="v4", origin="overlay", origin_iface=interface)
    return ctx["route-db"].update(e)


def process_overlay_full_dynamic(ctx, tables):
    if not isinstance(tables, list):
        log.error("routing message seems corrupt, expect array, got trash")
        return False
    update_required = False
    for route_entry in tables:
        ret = overlay_route_local_update_routes(ctx, route_entry)
        if ret == True: update_required = True
    # we do it in this way to do it one time, to reduce subsequent load
    # for the terminal
    if update_required:
        asyncio.ensure_future(route_db_changed(ctx))
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


def terminal_air_by_router_eth(data, ip_addr, proto):
    for e in data['terminal-air-ip-list']:
        if proto == 'v4':
            if e['router-addr-v4'] == ip_addr:
                return e['terminal-air-addr-v4']
        else:
            raise
    return None


def route_db_changed_non_tunnel(ctx):
    affected_tables = available_routing_tables(ctx['conf'])
    for entry in ctx["route-db"].db:
        if entry.origin == "config":
            # will not be configured locally, just for terminal
            # purpose
            continue
        if entry.state == "new":
            prefix     = entry.prefix
            prefix_len = entry.prefix_len
            interface  = entry.interface
            next_hop   = entry.next_hop
            # add default route too
            execute_route_add(ctx, prefix, prefix_len, next_hop, interface)

    affected_tables.add("main")
    affected_tables.add("default")
    execute_route_show(ctx, affected_tables)

    # now set routing table for terminals
    routes = []
    for entry in ctx["route-db"].db:
        r = {}
        if entry.origin == "config":
            prefix_full = "{}/{}".format(entry.prefix, entry.prefix_len)
            r['iface'] = entry.interface
            r['prefix'] = prefix
            r['next-hop'] = entry.next_hop
        else:
            iface = entry.origin_iface
            prefix_full = "{}/{}".format(entry.prefix, entry.prefix_len)
            interface  = entry.l1_iface_name
            next_hop   = entry.l1_next_hop_v4
            r['iface'] = interface
            r['prefix'] = prefix_full
            r['next-hop'] = next_hop
        routes.append(r)
    set_ip_routes(ctx, iface, routes)



def route_db_set_state_old(ctx):
    for entry in ctx["route-db"].db:
        if entry.state == "new":
            entry.state = "old"


async def route_db_changed(ctx):
    route_db_changed_non_tunnel(ctx)
    #route_db_changed_non_tunnel(ctx)
    route_db_set_state_old(ctx)


async def underlay_route_local_update(ctx, pl_l0_top_iface_name, l0_top_addr_v4):
    #log.debug("update local routes")
    route_data  = ctx['db-underlay'][pl_l0_top_iface_name][l0_top_addr_v4]

    # shared between l0 & l1
    prefix      = route_data['l0_prefix_v4']
    prefix_len  = route_data['l0_prefix_len_v4']

    # l0
    interface   = pl_l0_top_iface_name
    next_hop    = ctx['db-underlay'][pl_l0_top_iface_name]['terminal-data']['pl_l0_bottom_addr_v4']

    # l1
    l1_next_hop    = route_data['l1_top_addr_v4']
    l1_iface_name  = ctx['db-underlay'][pl_l0_top_iface_name]['terminal-data']['pl_l1_top_iface_name']

    # FIXME: save this mapping somewhere else
    ctx["l1-map"][pl_l0_top_iface_name] = l1_next_hop

    e = RouteEntry(prefix, prefix_len, next_hop, interface,
                   l1_next_hop_v4=l1_next_hop, l1_iface_name=l1_iface_name,
                   proto="v4", origin="underlay", origin_iface=pl_l0_top_iface_name)
    ret = ctx["route-db"].update(e)
    if ret:
        asyncio.ensure_future(route_db_changed(ctx))
        
        # new one, trigger update procedure



def process_underlay_terminal_local_rest(ctx, data):
    # where did OHNDL instance operates off?
    pl_l0_top_iface_name = data['terminal']['pl_l0_top_iface_name']

    # clean up everything from this particular neighbor,
    # remove old ones for now
    ctx['db-underlay'][pl_l0_top_iface_name] = dict()
    #route_flush_configured_rt_tables(ctx, iface_name=pl_l0_top_iface_name)
    ctx['db-underlay'][pl_l0_top_iface_name]['terminal-data'] = data['terminal']

    for route in data['neighbors']:
        l0_top_addr_v4 = route['l0_top_addr_v4']
        if l0_top_addr_v4 in ctx['db-underlay'][pl_l0_top_iface_name]:
            raise Exception("two or more routers with some l0 addr, config error?")
        ctx['db-underlay'][pl_l0_top_iface_name][l0_top_addr_v4] = route
        asyncio.ensure_future(underlay_route_local_update(ctx, pl_l0_top_iface_name, l0_top_addr_v4))
    return True


def process_underlay_gre(ctx, data):
    # See process_underlay_terminal_local_rest() for a complete
    # function where a) local routes are set and b) the terminal
    # is configured too

    # local interface name (com0, com1, ...)
    pl_l0_top_iface_name = data['terminal']['pl_l0_top_iface_name']
    for route in data['neighbors']:
        l0_top_addr_v4 = route['l0_top_addr_v4']
    return True


def process_underlay_message(ctx, data):
    iface_name = data['terminal']['pl_l0_top_iface_name']
    for iface_data in ctx['conf']['interfaces']:
        if not iface_data['name'] == iface_name:
            continue
        if iface_data['type'] == 'terminal-local-rest':
            return process_underlay_terminal_local_rest(ctx, data)
        elif iface_data['type'] == 'gre':
            return process_underlay_gre(ctx, data)
    raise Exception("interface type not specided for term {}".format(iface_name))


async def underlay_handle_rest_rx(request):
    ctx = request.app['ctx']
    # usually from OHNDL
    try:
        request_data = await request.json()
        ok = process_underlay_message(ctx, request_data)
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


def route_flush_configured_rt_tables(ctx, iface_name=None):
    configured_rt_tables = available_routing_tables(ctx["conf"])
    print("clean existing routing entries")
    cmd_base = "ip route flush"
    if iface_name:
        cmd_base += " dev {}".format(iface_name)
    for table in configured_rt_tables:
        cmd = "{} table {}".format(cmd_base, table)
        execute_command(cmd)


def init_routing_system(ctx):
    route_flush_configured_rt_tables(ctx)


def nft_flush_all_input_v4(ctx):
    # Flush rules in chain route_manager/input:
    cmd = "nft flush chain ip {} input".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)
    # Delete the chain NFT_TABLE_NAME/input:
    cmd = "nft delete chain ip {} input".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)


def nft_flush_all_input_v6(ctx):
    # Flush rules in chain route_manager/input:
    cmd = "nft flush chain ip6 {} input".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)
    # Delete the chain NFT_TABLE_NAME/input:
    cmd = "nft delete chain ip6 {} input".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)

def nft_destroy_default_set_v4(ctx):
    nft_flush_all_input_v4(ctx)
    # finally delete the table NFT_TABLE_NAME:
    cmd = "nft delete table ip {}".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)

def nft_destroy_default_set_v6(ctx):
    nft_flush_all_input_v6(ctx)
    # finally delete the table NFT_TABLE_NAME:
    cmd = "nft delete table ip6 {}".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)


def nft_destroy_default_set(ctx):
    nft_destroy_default_set_v4(ctx)
    nft_destroy_default_set_v6(ctx)


def nft_create_vanilla_set_input_v4(ctx):
    cmd = "nft add chain ip {} input ".format(NFT_TABLE_NAME)
    cmd += "{ type filter hook input priority 0; }"
    execute_command(cmd, suppress_output=True)
    # account data and accept
    cmd = "nft add rule ip {} input counter accept".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)


def nft_create_vanilla_set_preroute_v4(ctx):
    cmd = "nft add chain ip {} prerouting ".format(NFT_TABLE_NAME)
    cmd += "{ type filter hook prerouting priority 0; }"
    execute_command(cmd, suppress_output=True)
    # account data and accept
    cmd = "nft add rule ip {} prerouting counter accept".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=False)


def nft_create_vanilla_set_output_v4(ctx):
    cmd = "nft add chain ip {} output ".format(NFT_TABLE_NAME)
    cmd += "{ type filter hook output priority 0; }"
    execute_command(cmd, suppress_output=True)
    # account data and accept
    cmd = "nft add rule ip {} output counter accept".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)


def nft_create_vanilla_set_postroute_v4(ctx):
    cmd = "nft add chain ip {} postrouting ".format(NFT_TABLE_NAME)
    cmd += "{ type filter hook postrouting priority 0; }"
    execute_command(cmd, suppress_output=True)
    # account data and accept
    cmd = "nft add rule ip {} postrouting counter accept".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)


def nft_create_default_set_v4(ctx):
    cmd = "nft add table ip {}".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)

    nft_create_vanilla_set_input_v4(ctx)
    nft_create_vanilla_set_preroute_v4(ctx)
    nft_create_vanilla_set_output_v4(ctx)
    nft_create_vanilla_set_postroute_v4(ctx)


def nft_create_vanilla_set_input_v6(ctx):
    cmd = "nft add chain ip6 {} input ".format(NFT_TABLE_NAME)
    cmd += "{ type filter hook input priority 0; }"
    execute_command(cmd, suppress_output=True)
    # account data and accept
    cmd = "nft add rule ip6 {} input counter accept".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)


def nft_create_vanilla_set_preroute_v6(ctx):
    cmd = "nft add chain ip6 {} prerouting ".format(NFT_TABLE_NAME)
    cmd += "{ type filter hook prerouting priority 0; }"
    execute_command(cmd, suppress_output=True)
    # account data and accept
    cmd = "nft add rule ip6 {} prerouting counter accept".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=False)


def nft_create_vanilla_set_output_v6(ctx):
    cmd = "nft add chain ip6 {} output ".format(NFT_TABLE_NAME)
    cmd += "{ type filter hook output priority 0; }"
    execute_command(cmd, suppress_output=True)
    # account data and accept
    cmd = "nft add rule ip6 {} output counter accept".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)


def nft_create_vanilla_set_postroute_v6(ctx):
    cmd = "nft add chain ip6 {} postrouting ".format(NFT_TABLE_NAME)
    cmd += "{ type filter hook postrouting priority 0; }"
    execute_command(cmd, suppress_output=True)
    # account data and accept
    cmd = "nft add rule ip6 {} postrouting counter accept".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)


def nft_create_default_set_v6(ctx):
    cmd = "nft add table ip6 {}".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=True)

    nft_create_vanilla_set_input_v6(ctx)
    nft_create_vanilla_set_preroute_v6(ctx)
    nft_create_vanilla_set_output_v6(ctx)
    nft_create_vanilla_set_postroute_v6(ctx)


def nft_create_default_set(ctx):
    nft_create_default_set_v4(ctx)
    nft_create_default_set_v6(ctx)


def nft_add_generic_v4(ctx, chain_name, body):
    cmd = "nft add rule ip {} {} {}".format(NFT_TABLE_NAME, chain_name, body)
    execute_command(cmd, suppress_output=False)


def nft_add_generic_v6(ctx, chain_name, body):
    cmd = "nft add rule ip6 {} {} {}".format(NFT_TABLE_NAME, chain_name, body)
    execute_command(cmd, suppress_output=False)


def nft_add_all_chains_generic_v4(ctx, body):
    for chain in ("prerouting", "output", "postrouting"):
        nft_add_generic_v4(ctx, chain, body)


def nft_add_all_chains_generic_v6(ctx, body):
    for chain in ("prerouting", "output", "postrouting"):
        nft_add_generic_v6(ctx, chain, body)


def nft_add_configured_mark_rules_v4(ctx, selector):
    rule = selector["nft-rule"]
    table = selector['table']
    mark_no = ctx['rt-map'][table]
    nft_cmd = "{} mark set {}".format(rule, mark_no)
    nft_add_all_chains_generic_v4(ctx, nft_cmd)


def nft_add_configured_mark_rules_v6(ctx, selector):
    rule = selector["nft6-rule"]
    table = selector['table']
    mark_no = ctx['rt-map'][table]
    nft_cmd = "{} mark set {}".format(rule, mark_no)
    nft_add_all_chains_generic_v6(ctx, nft_cmd)


def nft_add_configured_mark_rules(ctx):
    for selector in ctx["conf"]['table-selectors']:
        if "nft-rule" in selector:
            nft_add_configured_mark_rules_v4(ctx, selector)
        elif "nft6-rule" in selector:
            nft_add_configured_mark_rules_v6(ctx, selector)
        else:
            log.error("rule not known: {}".format(selector))


def nft_show_all(ctx):
    cmd = "nft list table ip {}".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=False)
    cmd = "nft list table ip6 {}".format(NFT_TABLE_NAME)
    execute_command(cmd, suppress_output=False)


def nft_system_init(ctx):
    nft_destroy_default_set(ctx)
    nft_create_default_set(ctx)
    nft_add_configured_mark_rules(ctx)
    nft_show_all(ctx)


def setup_markers(ctx):
    """ based in the available tables we generate n different marks (1, 2, 3)
        later we can map from name (lowest_loss) to a mark and vice versa
        """
    ctx['rt-map'] = dict()
    ctx['rt-map-reverse'] = dict()
    base_mark = 0x1000
    policy_routes = available_routing_tables(ctx["conf"])
    print("prepase numerical marker/routing-table mapping:")
    for route in policy_routes:
        print("  {} <-> 0x{:02X}".format(route, base_mark))
        ctx['rt-map'][route] = base_mark
        ctx['rt-map-reverse'][route] = base_mark
        base_mark += 1

def rule_system_cleanup_v4(ctx):
    cmd = 'sudo ip -4 rule flush'
    execute_command(cmd, suppress_output=False)
    cmd = 'sudo ip -4 rule add from 0/0 priority 32766 table main'
    execute_command(cmd, suppress_output=False)
    cmd = 'sudo ip -4 rule add from 0/0 priority 32767 table default'
    execute_command(cmd, suppress_output=False)


def rule_system_cleanup_v6(ctx):
    cmd = 'sudo ip -6 rule flush'
    execute_command(cmd, suppress_output=False)
    cmd = 'sudo ip -6 rule add from ::/0 priority 32766 table main'
    execute_command(cmd, suppress_output=False)
    cmd = 'sudo ip -6 rule add from ::/0 priority 32767 table default'
    execute_command(cmd, suppress_output=False)


def rule_system_cleanup(ctx):
    rule_system_cleanup_v4(ctx)
    rule_system_cleanup_v6(ctx)


def rule_system_set_configured_v4(ctx):
    # this splices firewall marking and policy routes together,
    # routes with lower priorities are preferred
    print("Splice nft rules and policy routes for IPv4")
    rule_priority = 1000
    for name, mark_no in ctx['rt-map'].items():
        cmd = 'ip -4 rule add fwmark {} priority {} table {}'
        cmd = cmd.format(mark_no, rule_priority, name)
        execute_command(cmd, suppress_output=False)

    print("Set default IPv4 rule (higher preference than main/default!)")
    rule_priority = 2000
    default_table = ctx['conf']["default-table"]
    cmd = 'ip -4 rule add priority {} table {}'
    cmd = cmd.format(rule_priority, default_table)
    execute_command(cmd, suppress_output=False)


def rule_system_set_configured_v6(ctx):
    # this splices firewall marking and policy routes together,
    # routes with lower priorities are preferred
    print("Splice nft rules and policy routes for IPv6")
    rule_priority = 1000
    for name, mark_no in ctx['rt-map'].items():
        cmd = 'ip -6 rule add fwmark {} priority {} table {}'
        cmd = cmd.format(mark_no, rule_priority, name)
        execute_command(cmd, suppress_output=False)

    print("Set default IPv6 rule (higher preference than main/default!)")
    rule_priority = 2000
    default_table = ctx['conf']["default-table"]
    cmd = 'ip -6 rule add priority {} table {}'
    cmd = cmd.format(rule_priority, default_table)
    execute_command(cmd, suppress_output=False)


def rule_system_set_configured(ctx):
    rule_system_set_configured_v4(ctx)
    rule_system_set_configured_v6(ctx)


def rule_system_show(ctx):
    print("Ruleset IPv4:")
    cmd = 'ip -4 rule list'
    execute_command(cmd, suppress_output=False)
    print("Ruleset IPv6:")
    cmd = 'ip -6 rule list'
    execute_command(cmd, suppress_output=False)


def rule_system_init(ctx):
    rule_system_cleanup(ctx)
    rule_system_set_configured(ctx)
    rule_system_show(ctx)


def init_stack(ctx):
    setup_markers(ctx)
    init_routing_system(ctx)
    nft_system_init(ctx)
    rule_system_init(ctx)


def ctx_new(conf, args):
    ctx = dict()
    ctx['conf'] = conf
    ctx['args'] = args
    ctx['db-underlay'] = dict()
    ctx['db-underlay-last-updated'] = None
    ctx['db-overlay'] = list()
    ctx['db-overlay-last-updated'] = None
    return ctx


def setup_local_default_routes(ctx):

    for iface in ctx["conf"]["interfaces"]:
        if not "local-networks" in iface:
            continue
        for network in iface["local-networks"]:
                prefix = network["prefix"]
                prefix_len = network["prefix-len"]
                next_hop = iface["addr-v4"]
                interface = iface["l0-bottom-iface-name"]
                e = RouteEntry(prefix, prefix_len, next_hop, interface, origin="config")
                ctx["route-db"].update(e)


def main(conf, args):
    ctx = ctx_new(conf, args)
    init_stack(ctx)
    loop = asyncio.get_event_loop()
    http_init(ctx, loop)

    ctx["route-db"] = RouteDB()
    setup_local_default_routes(ctx)

    ctx["l1-map"] = dict()
    asyncio.ensure_future(route_broadcast(ctx))
    asyncio.ensure_future(route_db_gc(ctx))
    asyncio.ensure_future(route_renew(ctx))
    #asyncio.ensure_future(print_routes_periodically(ctx))
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
    parser.add_argument("--help-commands", help="show usefull command", action='store_true', default=False)
    parser.add_argument("-c", "--cinema-mode", help="show permantly routes", action='store_true',
                        default=False, dest="cinema")
    args = parser.parse_args()
    if args.help_commands:
        show_usefull_commands()
        sys.exit(0)
    if not args.configuration:
        err("Configuration required, please specify a valid file path, exiting now\n")
    return args


def load_configuration_file(args):
    with open(args.configuration) as json_data:
        return json.load(json_data)


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


def available_routing_tables(conf):
    tables = set()
    for selectors in conf['table-selectors']:
        tables.add(selectors['table'])
    tables.add(conf['default-table'])
    return tables


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


def init_logging(conf):
    log_level_conf = "warning"
    if "logging" in conf:
        if "level" in conf["logging"]:
            log_level_conf = conf["logging"]['level']
    numeric_level = getattr(logging, log_level_conf.upper(), None)
    if not isinstance(numeric_level, int):
        raise ConfigurationException('Invalid log level: {}'.format(numeric_level))
    logging.basicConfig(level=numeric_level, format='%(message)s')
    log.error("Log level configuration: {}".format(log_level_conf))


def show_usefull_commands():
    print("nft list table ip")
    print("nft list table ip6")
    print("ip -4 rule list")
    print("ip -6 rule list")
    print("ip -4 route show table highest_bandwidth")


def conf_init():
    args = parse_args()
    conf = load_configuration_file(args)
    init_logging(conf)
    check_conf(conf)
    return conf, args


def is_tool_available(name):
    try:
        devnull = open(os.devnull)
        subprocess.Popen([name], stdout=devnull, stderr=devnull).communicate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            return False
    return True


def check_applications(conf):
    apps = [["nft", "nftables"], ['ip', 'iproute2'] ]
    for app in apps:
        available = is_tool_available(app[0])
        if not available:
            print("{} not available, install {}, bye".format(app[0], app[1]))
            sys.exit(EXIT_FAILURE)


def proc_file_expect(path, number, err_text, exit_if_true=True):
    with open(path) as fd:
            data = fd.read()
            if int(data) != number:
                print("{} [{}]".format(err_text, path))
                print("try \"echo {} | sudo tee {}\"".format(number, path))
                if exit_if_true:
                    sys.exit(EXIT_FAILURE)
                time.sleep(2)


def check_forwarding(conf):
    path = "/proc/sys/net/ipv4/ip_forward"
    proc_file_expect(path, 1, "No IPv4 forwarding enabled")
    path = "/proc/sys/net/ipv6/conf/all/forwarding"
    proc_file_expect(path, 1, "No IPv6 forwarding enabled")


def check_filters(conf):
    path = "/proc/sys/net/ipv4/conf/all/rp_filter"
    proc_file_expect(path, 2, "reverse-path filter should be loose", exit_if_true=False)
    path = "/proc/sys/net/ipv4/conf/all/log_martians"
    proc_file_expect(path, 2, "log martians should be enabled in integration period", exit_if_true=False)


def check_environment(conf):
    check_applications(conf)
    check_forwarding(conf)
    check_filters(conf)


def check_priviledges():
    if os.geteuid() != 0:
        msg  = "You need to have root privileges to run this program.\n"
        msg += "Exiting. So sooory"
        print(msg)
        sys.exit(EXIT_FAILURE)


if __name__ == '__main__':
    sys.stderr.write("route-manager(c) - 2016, 2017\n")
    check_priviledges()
    conf, args = conf_init()
    check_environment(conf)
    main(conf, args)
