import argparse
import re
import subprocess
from datetime import datetime
import os
import shutil
import yaml
import sys
from pymongo import MongoClient
from bson import objectid, int64, ObjectId
from bson.errors import InvalidId


def objectid_representer(dumper, data):
    return dumper.represent_scalar("!bson.objectid.ObjectId", str(data))


def numberlong_representer(dumper, data):
    return dumper.represent_scalar("!bson.int64.Int64", str(data))


def null_representer(dumper, data):
    return dumper.represent_scalar("!NoneType", "None")


yaml.SafeDumper.add_representer(objectid.ObjectId, objectid_representer)
yaml.SafeDumper.add_representer(int64.Int64, numberlong_representer)
yaml.SafeDumper.add_representer(type(None), null_representer)


def store_as_yaml(obj, filename):
    with open(filename, "w") as out_file:
        yaml.safe_dump(obj, out_file)


class MongoDB:
    def __init__(self, connection_string="", db="waf"):
        if connection_string:
            self.client = MongoClient(connection_string)
            self.db = self.client[db]
        else:
            try:
                process = subprocess.Popen(
                    ["sudo /usr/local/bin/wsc -c 'cluster list mongo' | /bin/grep 'mongodb://' | /usr/bin/awk '{print $2}'"],
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
                mongo_uri = process.stdout.readline().strip()
                self.client = MongoClient(mongo_uri)
                self.db = self.client['waf']
            except:
                print("Cannot connect to local MongoDB, exiting")

    def fetch_all(self, collection_name, filter={}, excluded_fields=[]):
        res = []
        collections = self.db.collection_names()
        if collection_name in collections:
            storage = self.db[collection_name]
            excluded = {}
            for field in excluded_fields:
                excluded[field] = False
            if excluded:
                db_iterator = storage.find(filter, excluded)
            else:
                db_iterator = storage.find(filter)
            for doc in db_iterator:
                res.append(doc)
        return res

    def fetch_one(self, collection_name, filter={}, excluded_fields=[]):
        res = {}
        collections = self.db.collection_names()
        if collection_name in collections:
            storage = self.db[collection_name]
            excluded = {}
            for field in excluded_fields:
                excluded[field] = False
            if excluded:
                res = storage.find_one(filter, excluded)
            else:
                res = storage.find_one(filter)
        return res


def parse_cli_args(test_data=""):
    def parse_single_arg(s):
        id_or_list_of_ids_regex = re.compile("^([0-9a-f]{24},?\s*)+$", re.MULTILINE | re.IGNORECASE)
        if s.upper() == "ONLY_REQUIRED":  # Pre-defined value, means export only needed objects
            return True
        elif s.upper() == "NONE":  # Pre-defined value, means do not export any objects
            return False
        elif id_or_list_of_ids_regex.match(s):
            return [x.strip() for x in s.split(',')]
        else:
            return re.compile(s, re.IGNORECASE)

    parser = argparse.ArgumentParser(description='Export data from PT AF')
    parser.add_argument('MODE',
                        action='store',
                        choices=["all", "class"],
                        help='Mode of export. Use "all" to export all the supported classes or "class" to export exact class of objects')
    parser.add_argument('-c', '--class',
                        action='store',
                        dest='CLASS',
                        choices=["policies", "rules", "tags", "events", "alerts", "actions", "blacklist-ip", "blacklist-hosts", "firewall"],
                        required=' class ' in sys.argv,
                        help='Class of object(s) to export. Other classes will be exported only if needed')
    parser.add_argument('-f', '--folder',
                        action='store',
                        dest='FOLDER',
                        default="export_" + str(datetime.today().date()),
                        required=False,
                        help='Folder to store exported files, "export_' + str(datetime.today().date()) + '" by default')
    parser.add_argument('-p', '--policies',
                        action='store',
                        dest='POLICIES',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Policy to export, comma-separated list of IDs or name regex. Use NONE to do not export any. By default only policies required by other objects will be exported')
    parser.add_argument('-r', '--rules',
                        action='store',
                        dest='RULES',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Rules to export, comma-separated list of IDs or name regex. Use NONE to do not export any. By default only rules required by other objects will be exported')
    parser.add_argument('-t', '--tags',
                        action='store',
                        dest='TAGS',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Tags to export, comma-separated list of IDs or name regex. Use NONE to do not export any. By default only tags required by other objects will be exported')
    parser.add_argument('-e', '--events',
                        action='store',
                        dest='EVENTS',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Events to export, comma-separated list of IDs or name regex. Use NONE to do not export any. By default only events required by other objects will be exported')
    parser.add_argument('-a', '--alerts',
                        action='store',
                        dest='ALERTS',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Alerts to export, comma-separated list of IDs or name regex. Use NONE to do not export any. By default only alerts required by other objects will be exported')
    parser.add_argument('--actions',
                        action='store',
                        dest='ACTIONS',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Actions to export, comma-separated list of IDs or name regex. Use NONE to do not export any. By default only actions required by other objects will be exported')
    parser.add_argument('-b', '--blacklist-ip',
                        action='store',
                        dest='BLACKLIST',
                        choices=["all", "proxy", "vpn", "tor", "custom"],
                        default='all',
                        required=False,
                        help='Type of blacklisted IP record to export. By default all records will be exported')
    parser.add_argument('--firewall',
                        action='store',
                        dest='FIREWALL',
                        choices=["all", "firewall", "arbor", "checkpoint", "qrator"],
                        default='all',
                        required=False,
                        help='Tag of firewall rules to export. By default all records will be exported')
    parser.add_argument('--excludes',
                        action='store_true',
                        dest='DUMP_EXCLUDES',
                        required=False,
                        help='Export excludes as well. By default excludes won\'t be exported')
    parser.add_argument('--force-clean',
                        action='store_true',
                        dest='FORCE_CLEAN',
                        required=False,
                        help='Force clean target directory. By default tool will update target files if they exist')

    if test_data:
        args = parser.parse_args(test_data)
    else:
        args = parser.parse_args()

    args.EXPORT_POLICIES = parse_single_arg(args.POLICIES)
    args.EXPORT_RULES = parse_single_arg(args.RULES)
    args.EXPORT_TAGS = parse_single_arg(args.TAGS)
    args.EXPORT_EVENTS = parse_single_arg(args.EVENTS)
    args.EXPORT_ALERTS = parse_single_arg(args.ALERTS)
    args.EXPORT_ACTIONS = parse_single_arg(args.ACTIONS)

    del args.POLICIES
    del args.RULES
    del args.TAGS
    del args.EVENTS
    del args.ALERTS
    del args.ACTIONS
    del args.BLACKLIST
    del args.FIREWALL

    return args


class Run:
    def __init__(self, args, mongo):
        if not mongo:
            mongo = MongoDB()
        self.mongo = mongo
        self.args = args
        self.POLICIES_DIR = "policies"
        self.RULES_DIR = "rules"
        self.TAGS_DIR = "tags"
        self.EVENTS_DIR = "events"
        self.ALERTS_DIR = "alerts"
        self.ACTIONS_DIR = "actions"
        self.BLACKLIST_IP_DIR = "blacklist_ip"
        self.BLACKLIST_HOSTS_DIR = "blacklist_hosts"
        self.FIREWALL_DIR = "ipset"
        self.ALL_ACTIONS = list()
        self.ALL_ALERTS = list()
        self.ALL_EVENTS = list()
        self.ALL_POLICIES = list()
        self.ALL_RULES = list()
        self.ALL_TAGS = list()
        self.ALL_BLACKLIST_IP = list()
        self.ALL_BLACKLIST_HOSTS = list()
        self.ALL_FIREWALL = list()
        self.ACTIONS = list()
        self.ALERTS = list()
        self.EVENTS = list()
        self.POLICIES = list()
        self.RULES = list()
        self.TAGS = list()
        self.BLACKLIST_IP = list()
        self.BLACKLIST_HOSTS = list()
        self.FIREWALL = list()

    def bootstrap(self):
        self.ALL_ACTIONS = self.mongo.fetch_all('actions')
        self.ALL_ALERTS = self.mongo.fetch_all('alerts')
        self.ALL_EVENTS = self.mongo.fetch_all('events')
        self.ALL_POLICIES = self.mongo.fetch_all('policies')
        self.ALL_RULES = self.mongo.fetch_all('rules')
        self.ALL_TAGS = self.mongo.fetch_all('tags')
        self.ALL_BLACKLIST_IP = self.mongo.fetch_all('blacklist.ip')
        self.ALL_BLACKLIST_HOSTS = self.mongo.fetch_all('blacklist.hosts')
        self.ALL_FIREWALL = self.mongo.fetch_all('ipset')

    # Methods to get data for export
    def get_actions(self, actions_to_check=None):
        def clean(obj):
            res = obj
            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.EXPORT_ACTIONS) == bool:  # Simple condition
                    if self.args.EXPORT_ACTIONS:  # Dump all needed, confirm matching
                        return True
                    else:  # Do not export any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.EXPORT_ACTIONS) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.EXPORT_ACTIONS) == list:  # List of IDs
                if str(o['_id']) in self.args.EXPORT_ACTIONS:
                    return True
            else:  # Regex of name
                if self.args.EXPORT_ACTIONS.match(o['name'].encode('utf-8')):
                    return True

            return False

        # Fulfill the list of candidates
        res = list()
        if actions_to_check is None:  # Primary class,check all the objects
            for o in self.ALL_ACTIONS:
                if matched(o):
                    res.append(clean(o))
        else:  # Dependent class, check only objects from received list
            for oid in actions_to_check:
                try:
                    action_id = ObjectId(oid)
                except InvalidId:
                    print("[!] Action ID {} is invalid, ignoring".format(oid))
                    continue
                for o in self.ALL_ACTIONS:
                    if o["_id"] == action_id:
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)

        # Process the list of candidates and extract dependencies (if any)
        for o in res:
            if o not in self.ACTIONS:
                # Actions have no dependent classes, so just add object to the list for export
                self.ACTIONS.append(o)

    def get_alerts(self, alerts_to_check=None):
        def clean(obj):
            res = obj
            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.EXPORT_ALERTS) == bool:  # Simple condition
                    if self.args.EXPORT_ALERTS:  # Dump all needed, confirm matching
                        return True
                    else:  # Do not export any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.EXPORT_ALERTS) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.EXPORT_ALERTS) == list:  # List of IDs
                if str(o['_id']) in self.args.EXPORT_ALERTS:
                    return True
            else:  # Regex of name
                if self.args.EXPORT_ALERTS.match(o['name'].encode('utf-8')):
                    return True

            return False

        def get_dependent(o):
            events = set()
            actions = set()
            if "events" in o.keys():
                for e in o["events"]:
                    events.add(str(e))
            if "actions" in o.keys():
                for a in o["actions"]:
                    actions.add(str(a))

            return actions, events

        def get_parent(o):
            parent_alert = set()
            if "parent_alert" in o.keys() and o["parent_alert"]:
                parent_alert.add(str(o["parent_alert"]))
            return parent_alert

        # Fulfill the list of candidates
        res = list()
        parent_alerts = set()
        if alerts_to_check is None:  # Primary class,check all the objects
            for o in self.ALL_ALERTS:
                if matched(o):
                    res.append(clean(o))
                    parent_alerts |= get_parent(o)
        else:  # Dependent class, check only objects from received list
            for oid in alerts_to_check:
                try:
                    alert_id = ObjectId(oid)
                except InvalidId:
                    print("[!] Alert ID {} is invalid, ignoring".format(oid))
                    continue
                for o in self.ALL_ALERTS:
                    if o["_id"] == alert_id:
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)
                                parent_alerts |= get_parent(o)

        # Recursively append parent alerts to the list of candidates
        while parent_alerts:
            oid = parent_alerts.pop()
            for o in self.ALL_ALERTS:
                if ObjectId(oid) == o['_id']:
                    if clean(o) not in res:
                        res.append(clean(o))
                        parent_alerts |= get_parent(o)

        # Process the list of candidates and extract dependencies (if any)
        dependent_events = set()
        dependent_actions = set()
        for o in res:
            if o not in self.ALERTS:
                self.ALERTS.append(o)
                (new_actions, new_events) = get_dependent(o)
                dependent_events |= new_events
                dependent_actions |= new_actions

        return list(dependent_actions), list(dependent_events)

    def get_events(self, events_to_check=None):
        def clean(obj):
            res = obj
            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.EXPORT_EVENTS) == bool:  # Simple condition
                    if self.args.EXPORT_EVENTS:  # Dump all needed, confirm matching
                        return True
                    else:  # Do not export any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.EXPORT_EVENTS) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.EXPORT_EVENTS) == list:  # List of IDs
                if str(o['_id']) in self.args.EXPORT_EVENTS:
                    return True
            else:  # Regex of name
                if self.args.EXPORT_EVENTS.match(o['name'].encode('utf-8')):
                    return True

            return False

        def get_dependent(o):
            def check_condition(c):
                def get_rules_by_id(c):
                    rules = set()
                    if type(c['value']) == list:
                        rules |= set(c['value'])
                    else:
                        rules.add(c['value'])
                    return rules

                def get_rules_by_name(c):
                    def rule_id_by_name(s):
                        for r in self.ALL_RULES:
                            if r['name'] == s:
                                return str(r['_id'])

                        return None

                    rules = set()
                    if type(c['value']) == list:
                        for rule_name in c['value']:
                            rule_id = rule_id_by_name(rule_name)
                            if rule_id is not None:
                                rules.add(rule_id)
                    else:
                        rule_id = rule_id_by_name(c['value'])
                        if rule_id is not None:
                            rules.add(rule_id)
                    return rules

                def get_tags_by_id(c):
                    tags = set()
                    if type(c['value']) == list:
                        tags |= set(c['value'])
                    else:
                        tags.add(c['value'])
                    return tags

                def get_tags_by_name(c):
                    def tag_id_by_name(s):
                        for t in self.ALL_TAGS:
                            if t['name'] == s:
                                return str(t['_id'])

                        return None

                    tags = set()
                    if type(c['value']) == list:
                        for tag_name in c['value']:
                            tag_id = tag_id_by_name(tag_name)
                            if tag_id is not None:
                                tags.add(tag_id)
                    else:
                        tag_id = tag_id_by_name(c['value'])
                        if tag_id is not None:
                            tags.add(tag_id)
                    return tags

                rules = set()
                tags = set()
                for v in c['variables']:
                    if v['name'] == "EVENT_TAG.NAME":
                        tags |= get_tags_by_name(c)
                    elif v['name'] == "EVENT_TAG.ID":
                        tags |= get_tags_by_id(c)
                    elif v['name'] == "POLICY_RULE":
                        rules |= get_rules_by_id(c)
                    elif v['name'] == "EVENT_ID":
                        rules |= get_rules_by_name(c)
                return rules, tags

            def check_list_of_conditions(l):
                rules = set()
                tags = set()
                for c in l:
                    if len(c.keys()) == 1:  # AND or OR
                        new_rules, new_tags = check_list_of_conditions(c[c.keys()[0]])
                        rules |= new_rules
                        tags |= new_tags
                    else:  # Simple equation
                        new_rules, new_tags = check_condition(c)
                        rules |= new_rules
                        tags |= new_tags

                return rules, tags

            tags = set()
            rules = set()

            if len(o['condition'].keys()) == 1:  # AND or OR
                rules, tags = check_list_of_conditions(o['condition'][o['condition'].keys()[0]])
            else:
                rules, tags = check_condition(o['condition'])

            return rules, tags

        def get_parent(o):
            parent_event = set()
            if "parent_event" in o.keys() and o["parent_event"]:
                parent_event.add(str(o["parent_event"]))
            return parent_event

        # Fulfill the list of candidates
        res = list()
        parent_events = set()
        if events_to_check is None:  # Primary class,check all the objects
            for o in self.ALL_EVENTS:
                if matched(o):
                    res.append(clean(o))
                    parent_events |= get_parent(o)
        else:  # Dependent class, check only objects from received list
            for oid in events_to_check:
                try:
                    event_id = ObjectId(oid)
                except InvalidId:
                    print("[!] Event ID {} is invalid, ignoring".format(oid))
                    continue
                for o in self.ALL_EVENTS:
                    if o["_id"] == event_id:
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)
                                parent_events |= get_parent(o)

        # Recursively append parent alerts to the list of candidates
        while parent_events:
            oid = parent_events.pop()
            for o in self.ALL_EVENTS:
                if ObjectId(oid) == o['_id']:
                    if clean(o) not in res:
                        res.append(clean(o))
                        parent_events |= get_parent(o)

        # Process the list of candidates and extract dependencies (if any)
        dependent_tags = set()
        dependent_rules = set()
        for o in res:
            if o not in self.EVENTS:
                self.EVENTS.append(o)
                (new_rules, new_tags) = get_dependent(o)
                dependent_rules |= new_rules
                dependent_tags |= new_tags

        return list(dependent_rules), list(dependent_tags)

    def get_policies(self, policies_to_check=None):
        def clean(obj):
            protectors = ["AuthLDAP", "AuthOracle", "BlacklistProtector", "CSPProtector",
                          "CSRFProtector", "DDoSProtector", "HMMProtector", "HTTPProtector",
                          "ICAPProtector", "JSONProtector", "OpenRedirectProtector", "ResponseFilter",
                          "RobotProtector", "RuleEngine", "RVPProtector", "ScriptEngine",
                          "SessionCookieProtector", "SQLiProtector", "XMLProtector",
                          "XSSProtector"]
            wafjs_modules = ["botdetector", "domauth", "domcleaner", "domdetective"]
            res = obj
            res['template_id'] = None
            if not self.args.DUMP_EXCLUDES:  # Clean filters
                # Clean policy filter
                res['filters'] = list()
                # Clean protectors' filters
                for p in protectors:
                    if p in res.keys() and res[p]:
                        if 'filters' in res[p].keys():
                            res[p]['filters'] = list()
                # Clean filters for WafJs modules
                for m in wafjs_modules:
                    if 'filters' in res["WafJsProtector"][m].keys():
                        res["WafJsProtector"][m]['filters'] = list()
                    if 'custom_filter' in res["WafJsProtector"][m].keys():
                        res["WafJsProtector"][m]['custom_filter'] = None

            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.EXPORT_POLICIES) == bool:  # Simple condition
                    if self.args.EXPORT_POLICIES:  # Dump all needed, confirm matching
                        return True
                    else:  # Do not export any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.EXPORT_POLICIES) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.EXPORT_POLICIES) == list:  # List of IDs
                if str(o['_id']) in self.args.EXPORT_POLICIES:
                    return True
            else:  # Regex of name
                if self.args.EXPORT_POLICIES.match(o['name'].encode('utf-8')):
                    return True

            return False

        def get_dependent(o):
            rules = set()
            for r in self.ALL_RULES:
                if 'policies' in r.keys() and r['policies']:
                    if o['_id'] in r['policies']:
                        rules.add(r['_id'])

            return rules

        # Fulfill the list of candidates
        res = list()
        if policies_to_check is None:  # Primary class,check all the objects
            for o in self.ALL_POLICIES:
                if matched(o):
                    res.append(clean(o))
        else:  # Dependent class, check only objects from received list
            for oid in policies_to_check:
                for o in self.ALL_POLICIES:
                    if o["_id"] == ObjectId(oid):
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)

        # Process the list of candidates and extract dependencies (if any)
        dependent_rules = set()
        for o in res:
            if o not in self.POLICIES:
                self.POLICIES.append(o)
                dependent_rules |= get_dependent(o)

        return list(dependent_rules)

    def get_rules(self, rules_to_check=None):
        def clean(obj):
            res = obj
            res['template_id'] = list()
            if rules_to_check is None:  # Do not clean policy for dependent rules
                res['custom_policies'] = list()
                res['policies'] = list()
            if not self.args.DUMP_EXCLUDES:
                res['filters'] = list()
            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.EXPORT_RULES) == bool:  # Simple condition
                    if self.args.EXPORT_RULES:  # Dump all needed, confirm matching
                        return True
                    else:  # Do not export any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.EXPORT_RULES) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.EXPORT_RULES) == list:  # List of IDs
                if str(o['_id']) in self.args.EXPORT_RULES:
                    return True
            else:  # Regex of name
                if self.args.EXPORT_RULES.match(o['name'].encode('utf-8')):
                    return True

            return False

        def get_dependent(o):
            tags = set()
            actions = set()
            if "tags" in o.keys():
                for t in o["tags"]:
                    tags.add(str(t))
            if "actions" in o.keys():
                for a in o["actions"]:
                    actions.add(str(a))

            return actions, tags

        # Fulfill the list of candidates
        res = list()
        if rules_to_check is None:  # Primary class,check all the objects
            for o in self.ALL_RULES:
                if matched(o):
                    res.append(clean(o))
        else:  # Dependent class, check only objects from received list
            for oid in rules_to_check:
                try:
                    rule_id = ObjectId(oid)
                except InvalidId:
                    print("[!] Action ID {} is invalid, ignoring".format(oid))
                    continue
                for o in self.ALL_RULES:
                    if o["_id"] == rule_id:
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)

        # Process the list of candidates and extract dependencies (if any)
        dependent_tags = set()
        dependent_actions = set()
        for o in res:
            if o not in self.RULES:
                self.RULES.append(o)
                (new_actions, new_tags) = get_dependent(o)
                dependent_tags |= new_tags
                dependent_actions |= new_actions

        return list(dependent_actions), list(dependent_tags)

    def get_tags(self, tags_to_check=None):
        def clean(obj):
            res = obj
            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.EXPORT_TAGS) == bool:  # Simple condition
                    if self.args.EXPORT_TAGS:  # Dump all needed, confirm matching
                        return True
                    else:  # Do not export any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.EXPORT_TAGS) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.EXPORT_TAGS) == list:  # List of IDs
                if str(o['_id']) in self.args.EXPORT_TAGS:
                    return True
            else:  # Regex of name
                if self.args.EXPORT_TAGS.match(o['name'].encode("utf-8")):
                    return True

            return False

        # Fulfill the list of candidates
        res = list()
        if tags_to_check is None:  # Primary class,check all the objects
            for o in self.ALL_TAGS:
                if matched(o):
                    res.append(clean(o))
        else:  # Dependent class, check only objects from received list
            for oid in tags_to_check:
                try:
                    tag_id = ObjectId(oid)
                except InvalidId:
                    print("[!] Tag ID {} is invalid, ignoring".format(oid))
                    continue
                for o in self.ALL_TAGS:
                    if o["_id"] == tag_id:
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)

        # Process the list of candidates and extract dependencies (if any)
        for o in res:
            if o not in self.TAGS:
                # Tags have no dependent classes, so just add object to the list for export
                self.TAGS.append(o)

    def get_blacklist_ip(self):
        def clean(obj):
            res = obj
            return res

        def matched(o):
            if self.args.EXPORT_BLACKLIST == 'all':  # Export all the records
                return True
            else:  # Export only exact type
                if self.args.EXPORT_BLACKLIST == 'vpn':
                    return o['type'] == 'VPN'
                elif self.args.EXPORT_BLACKLIST == 'proxy':
                    return o['type'] == 'Anonymous'
                elif self.args.EXPORT_BLACKLIST == 'tor':
                    return o['type'] == 'TOR'
                elif self.args.EXPORT_BLACKLIST == 'custom':
                    return o['type'] == 'Custom'

            return False

        # Fulfill the list of candidates
        res = list()
        for o in self.ALL_BLACKLIST_IP:
            if matched(o):
                res.append(clean(o))

        # Process the list of candidates and extract dependencies (if any)
        for o in res:
            if o not in self.BLACKLIST_IP:
                # Blacklist IPs have no dependent classes, so just add object to the list for export
                self.BLACKLIST_IP.append(o)

    def get_blacklist_hosts(self):
        def clean(obj):
            res = obj
            return res

        def matched(o):
            # Always export all the blacklist hosts
            return True

        # Fulfill the list of candidates
        res = list()
        for o in self.ALL_BLACKLIST_HOSTS:
            if matched(o):
                res.append(clean(o))

        # Process the list of candidates and extract dependencies (if any)
        for o in res:
            if o not in self.BLACKLIST_HOSTS:
                # Blacklist hosts have no dependent classes, so just add object to the list for export
                self.BLACKLIST_HOSTS.append(o)

    def get_firewall(self):
        def clean(obj):
            res = obj
            return res

        def matched(o):
            if self.args.EXPORT_FIREWALL == 'all':  # Export all the records
                return True
            else:  # Export only exact class
                return self.args.EXPORT_FIREWALL == o['tag']

        def get_dependent(o):
            actions = set()
            if "action_oid" in o.keys():
                actions.add(o['action_oid'])

            return actions

        # Fulfill the list of candidates
        res = list()
        for o in self.ALL_FIREWALL:
            if matched(o):
                res.append(clean(o))

        # Process the list of candidates and extract dependencies (if any)
        dependent_actions = set()
        for o in res:
            if o not in self.FIREWALL:
                self.FIREWALL.append(o)
                dependent_actions |= get_dependent(o)

        return list(dependent_actions)

    # Methods to store data
    def store_actions(self, form="yaml"):
        store_path = os.path.join(self.args.FOLDER, self.ACTIONS_DIR)
        if not os.path.exists(store_path):
            os.mkdir(store_path)
        if form == "yaml":
            for o in self.ACTIONS:
                store_as_yaml(o, os.path.join(store_path, str(o['_id']) + ".yml"))
        else:
            raise NotImplementedError("Storing as {} isn't implemented".format(form))

    def store_alerts(self, form="yaml"):
        store_path = os.path.join(self.args.FOLDER, self.ALERTS_DIR)
        if not os.path.exists(store_path):
            os.mkdir(store_path)
        if form == "yaml":
            for o in self.ALERTS:
                store_as_yaml(o, os.path.join(store_path, str(o['_id']) + ".yml"))
        else:
            raise NotImplementedError("Storing as {} isn't implemented".format(form))

    def store_events(self, form="yaml"):
        store_path = os.path.join(self.args.FOLDER, self.EVENTS_DIR)
        if not os.path.exists(store_path):
            os.mkdir(store_path)
        if form == "yaml":
            for o in self.EVENTS:
                store_as_yaml(o, os.path.join(store_path, str(o['_id']) + ".yml"))
        else:
            raise NotImplementedError("Storing as {} isn't implemented".format(form))

    def store_policies(self, form="yaml"):
        store_path = os.path.join(self.args.FOLDER, self.POLICIES_DIR)
        if not os.path.exists(store_path):
            os.mkdir(store_path)
        if form == "yaml":
            for o in self.POLICIES:
                store_as_yaml(o, os.path.join(store_path, str(o['_id']) + ".yml"))
        else:
            raise NotImplementedError("Storing as {} isn't implemented".format(form))

    def store_rules(self, form="yaml"):
        store_path = os.path.join(self.args.FOLDER, self.RULES_DIR)
        if not os.path.exists(store_path):
            os.mkdir(store_path)
        if form == "yaml":
            for o in self.RULES:
                store_as_yaml(o, os.path.join(store_path, str(o['_id']) + ".yml"))
        else:
            raise NotImplementedError("Storing as {} isn't implemented".format(form))

    def store_tags(self, form="yaml"):
        store_path = os.path.join(self.args.FOLDER, self.TAGS_DIR)
        if not os.path.exists(store_path):
            os.mkdir(store_path)
        if form == "yaml":
            for o in self.TAGS:
                store_as_yaml(o, os.path.join(store_path, str(o['_id']) + ".yml"))
        else:
            raise NotImplementedError("Storing as {} isn't implemented".format(form))

    def store_blacklist_ip(self, form="yaml"):
        store_path = os.path.join(self.args.FOLDER, self.BLACKLIST_IP_DIR)
        if not os.path.exists(store_path):
            os.mkdir(store_path)
        if form == "yaml":
            for o in self.BLACKLIST_IP:
                store_as_yaml(o, os.path.join(store_path, str(o['_id']) + ".yml"))
        else:
            raise NotImplementedError("Storing as {} isn't implemented".format(form))

    def store_blacklist_hosts(self, form="yaml"):
        store_path = os.path.join(self.args.FOLDER, self.BLACKLIST_HOSTS_DIR)
        if not os.path.exists(store_path):
            os.mkdir(store_path)
        if form == "yaml":
            for o in self.BLACKLIST_HOSTS:
                store_as_yaml(o, os.path.join(store_path, str(o['_id']) + ".yml"))
        else:
            raise NotImplementedError("Storing as {} isn't implemented".format(form))

    def store_firewall(self, form="yaml"):
        store_path = os.path.join(self.args.FOLDER, self.FIREWALL_DIR)
        if not os.path.exists(store_path):
            os.mkdir(store_path)
        if form == "yaml":
            for o in self.FIREWALL:
                store_as_yaml(o, os.path.join(store_path, str(o['_id']) + ".yml"))
        else:
            raise NotImplementedError("Storing as {} isn't implemented".format(form))

    def store(self, form="yaml"):
        if not os.path.exists(self.args.FOLDER):
            os.mkdir(self.args.FOLDER)
        elif self.args.FORCE_CLEAN:
            for filename in os.listdir(self.args.FOLDER):
                file_path = os.path.join(self.args.FOLDER, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print('Failed to delete %s. Reason: %s' % (file_path, e))

        self.store_tags(form)
        self.store_rules(form)
        self.store_policies(form)
        self.store_events(form)
        self.store_alerts(form)
        self.store_actions(form)
        self.store_blacklist_ip(form)
        self.store_blacklist_hosts(form)
        self.store_firewall(form)

    def go_single(self):
        if self.args.CLASS == "actions":
            self.get_actions()
        elif self.args.CLASS == "alerts":
            (actions_from_alerts, events) = self.get_alerts()
            (rules, tags_from_events) = self.get_events(events)
            (actions_from_rules, tags_from_rules) = self.get_rules(rules)
            self.get_actions(actions_from_alerts+actions_from_rules)
            self.get_tags(tags_from_events+tags_from_rules)
        elif self.args.CLASS == "events":
            (rules, tags_from_events) = self.get_events()
            (actions, tags_from_rules) = self.get_rules(rules)
            self.get_actions(actions)
            self.get_tags(tags_from_events+tags_from_rules)
        elif self.args.CLASS == "policies":
            rules = self.get_policies()
            (actions, tags) = self.get_rules(rules)
            self.get_tags(tags)
            self.get_actions(actions)
        elif self.args.CLASS == "rules":
            (actions, tags) = self.get_rules()
            self.get_tags(tags)
            self.get_actions(actions)
        elif self.args.CLASS == "tags":
            self.get_tags()
        elif self.args.CLASS == "blacklist-ip":
            self.get_blacklist_ip()
        elif self.args.CLASS == "blacklist-hosts":
            self.get_blacklist_hosts()
        elif self.args.CLASS == "firewall":
            actions = self.get_firewall()
            self.get_actions(actions)
        else:
            raise KeyError("Unknown class to export: {}".format(self.args.CLASS))

    def go_all(self):
        any_re = re.compile(".*", re.IGNORECASE)
        # Export all the actions
        self.args.CLASS = 'actions'
        self.args.EXPORT_ACTIONS = any_re
        self.go_single()

        # Export all the alerts
        self.args.CLASS = 'alerts'
        self.args.EXPORT_ALERTS = any_re
        self.go_single()

        # Export all the events
        self.args.CLASS = 'events'
        self.args.EXPORT_EVENTS = any_re
        self.go_single()

        # Export all the policies
        self.args.CLASS = 'policies'
        self.args.EXPORT_POLICIES = any_re
        self.go_single()

        # Export all the rules
        self.args.CLASS = 'rules'
        self.args.EXPORT_RULES = any_re
        self.go_single()

        # Export all the tags
        self.args.CLASS = 'tags'
        self.args.EXPORT_TAGS = any_re
        self.go_single()

        # Export all the blacklisted IPs
        self.args.CLASS = 'blacklist-ip'
        self.args.EXPORT_BLACKLIST = 'all'
        self.go_single()

        # Export all the blacklisted hosts
        self.args.CLASS = 'blacklist-hosts'
        self.go_single()

        # Export all the firewall rules
        self.args.CLASS = 'firewall'
        self.args.EXPORT_FIREWALL = 'all'
        self.go_single()

    def go(self):
        if self.args.MODE == "all":
            self.go_all()
        else:
            self.go_single()


if __name__ == "__main__":
    r = Run(parse_cli_args(), MongoDB())
    r.bootstrap()

    # Get data
    r.go()

    # Dump to files
    r.store()

    print("DONE!")
