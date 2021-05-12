import argparse
import re
import subprocess
from datetime import datetime
import os
import yaml
from pymongo import MongoClient
from bson import objectid, int64, ObjectId
from bson.errors import InvalidId
from copy import deepcopy


def objectid_constructor(loader, data):
    return objectid.ObjectId(loader.construct_scalar(data))


def numberlong_constructor(loader, data):
    return int64.Int64(loader.construct_scalar(data))


def null_constructor(loader, data):
    return None


yaml.add_constructor('!bson.objectid.ObjectId', objectid_constructor)
yaml.add_constructor('!bson.int64.Int64', numberlong_constructor)
yaml.add_constructor('!NoneType', null_constructor)


def load_from_yaml(filename):
    with open(filename, "r") as in_file:
        obj = yaml.load(in_file)
    return obj


class MongoDB:
    def __init__(self, connection_string="", db="waf"):
        if connection_string:
            self.client = MongoClient(connection_string)
            self.db = self.client[db]
        else:
            try:
                process = subprocess.Popen(
                    [
                        "sudo /usr/local/bin/wsc -c 'cluster list mongo' | /bin/grep 'mongodb://' | /usr/bin/awk '{print $2}'"],
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

    def replace_one(self, collection_name, filter, replacement):
        if type(filter) == str:  # Means filter by ObjectId
            try:
                filter = {"_id": ObjectId(filter)}
            except InvalidId:
                print("[!] Object ID {} is invalid, ignoring".format(filter))
                return

        storage = self.db[collection_name]
        storage.find_one_and_replace(filter, replacement, upsert=True)

    def update_one(self, collection_name, filter, update):
        if type(filter) == str:  # Means filter by ObjectId
            try:
                filter = {"_id": ObjectId(filter)}
            except InvalidId:
                print("[!] Object ID {} is invalid, ignoring".format(filter))
                return

        storage = self.db[collection_name]
        storage.find_one_and_update(filter, update)

    def delete_one(self, collection_name, filter):
        if type(filter) == str:  # Means filter by ObjectId
            try:
                filter = {"_id": ObjectId(filter)}
            except InvalidId:
                print("[!] Object ID {} is invalid, ignoring".format(filter))
                return

        storage = self.db[collection_name]
        storage.delete_one(filter)


def parse_cli_args(test_data=""):
    def parse_single_arg(s):
        id_or_list_of_ids_regex = re.compile("^([0-9a-f]{24},?\s*)+$", re.MULTILINE | re.IGNORECASE)
        if s.upper() == "ONLY_REQUIRED":  # Pre-defined value, means import only needed objects
            return True
        elif s.upper() == "NONE":  # Pre-defined value, means do not import any objects
            return False
        elif id_or_list_of_ids_regex.match(s):
            return [x.strip() for x in s.split(',')]
        else:
            return re.compile(s, re.IGNORECASE)

    parser = argparse.ArgumentParser(description='Import data to PT AF')
    parser.add_argument('CLASS',
                        action='store',
                        choices=["all", "policies", "rules", "tags", "events", "alerts", "actions", "blacklist-ip",
                                 "blacklist-hosts", "firewall"],
                        help='Class of object(s) to import. Use "all" to import all the supported classes. Other classes will be imported only if needed')
    parser.add_argument('-f', '--folder',
                        action='store',
                        dest='FOLDER',
                        default="export_" + str(datetime.today().date()),
                        required=False,
                        help='Folder to get exported files, "export_' + str(datetime.today().date()) + '" by default')
    parser.add_argument('-p', '--policies',
                        action='store',
                        dest='POLICIES',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Policy to import, comma-separated list of IDs or name regex. Use NONE to do not import any. If class of imported objects is defined, only policies required by these objects will be imported')
    parser.add_argument('-r', '--rules',
                        action='store',
                        dest='RULES',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Rules to import, comma-separated list of IDs or name regex. Use NONE to do not import any. If class of imported objects is defined, only rules required by these objects will be imported')
    parser.add_argument('-t', '--tags',
                        action='store',
                        dest='TAGS',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Tags to import, comma-separated list of IDs or name regex. Use NONE to do not import any. By default only tags required by other objects will be imported')
    parser.add_argument('-e', '--events',
                        action='store',
                        dest='EVENTS',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Events to import, comma-separated list of IDs or name regex. Use NONE to do not import any. By default only events required by other objects will be imported')
    parser.add_argument('-a', '--alerts',
                        action='store',
                        dest='ALERTS',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Alerts to import, comma-separated list of IDs or name regex. Use NONE to do not import any. By default only alerts required by other objects will be imported')
    parser.add_argument('--actions',
                        action='store',
                        dest='ACTIONS',
                        default='ONLY_REQUIRED',
                        required=False,
                        help='Actions to import, comma-separated list of IDs or name regex. Use NONE to do not import any. By default only actions required by other objects will be imported')
    parser.add_argument('-b', '--blacklist-ip',
                        action='store',
                        dest='IMPORT_BLACKLIST',
                        choices=["all", "proxy", "vpn", "tor", "custom"],
                        default='all',
                        required=False,
                        help='Type of blacklisted IP record to import. By default all records will be imported')
    parser.add_argument('--firewall',
                        action='store',
                        dest='IMPORT_FIREWALL',
                        choices=["all", "firewall", "arbor", "checkpoint", "qrator"],
                        default='all',
                        required=False,
                        help='Tag of firewall rules to import. By default all records will be imported')
    parser.add_argument('--excludes',
                        action='store_true',
                        dest='IMPORT_EXCLUDES',
                        required=False,
                        help='Import excludes as well. By default excludes won\'t be imported')
    parser.add_argument('--force-update',
                        action='store_true',
                        dest='FORCE_REPLACE',
                        required=False,
                        help='Force replace existing objects. By default existing objects will be updated by newer data only')
    parser.add_argument('--delete-extra-custom',
                        action='store_true',
                        dest='DELETE_EXTRA_CUSTOM',
                        required=False,
                        help='Delete custom objects exist in database but absent in ruleset')
    parser.add_argument('--disable-extra-custom',
                        action='store_true',
                        dest='DISABLE_EXTRA_CUSTOM',
                        required=False,
                        help='Disable custom rules and alerts exist in database but absent in ruleset')
    parser.add_argument('--delete-extra-system',
                        action='store_true',
                        dest='DELETE_EXTRA_SYSTEM',
                        required=False,
                        help='Delete system objects exist in database but absent in ruleset')
    parser.add_argument('--disable-extra-system',
                        action='store_true',
                        dest='DISABLE_EXTRA_SYSTEM',
                        required=False,
                        help='Disable system rules and alerts exist in database but absent in ruleset')
    parser.add_argument('--debug',
                        action='store_true',
                        dest='DEBUG',
                        required=False,
                        help='Debug output')

    if test_data:
        args = parser.parse_args(test_data)
    else:
        args = parser.parse_args()

    args.IMPORT_POLICIES = parse_single_arg(args.POLICIES)
    args.IMPORT_RULES = parse_single_arg(args.RULES)
    args.IMPORT_TAGS = parse_single_arg(args.TAGS)
    args.IMPORT_EVENTS = parse_single_arg(args.EVENTS)
    args.IMPORT_ALERTS = parse_single_arg(args.ALERTS)
    args.IMPORT_ACTIONS = parse_single_arg(args.ACTIONS)

    del args.POLICIES
    del args.RULES
    del args.TAGS
    del args.EVENTS
    del args.ALERTS
    del args.ACTIONS

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
        self.STORED_ACTIONS = list()
        self.STORED_ALERTS = list()
        self.STORED_EVENTS = list()
        self.STORED_POLICIES = list()
        self.STORED_RULES = list()
        self.STORED_TAGS = list()
        self.STORED_BLACKLIST_IP = list()
        self.STORED_BLACKLIST_HOSTS = list()
        self.STORED_FIREWALL = list()
        self.LOADED_ACTIONS = list()
        self.LOADED_ALERTS = list()
        self.LOADED_EVENTS = list()
        self.LOADED_POLICIES = list()
        self.LOADED_RULES = list()
        self.LOADED_TAGS = list()
        self.LOADED_BLACKLIST_IP = list()
        self.LOADED_BLACKLIST_HOSTS = list()
        self.LOADED_FIREWALL = list()
        self.ACTIONS = list()
        self.ALERTS = list()
        self.EVENTS = list()
        self.POLICIES = list()
        self.RULES = list()
        self.TAGS = list()
        self.BLACKLIST_IP = list()
        self.BLACKLIST_HOSTS = list()
        self.FIREWALL = list()
        self.ACTIONS_EXTRA_CUSTOM = list()
        self.ACTIONS_EXTRA_SYSTEM = list()
        self.ALERTS_EXTRA_CUSTOM = list()
        self.ALERTS_EXTRA_SYSTEM = list()
        self.EVENTS_EXTRA_CUSTOM = list()
        self.EVENTS_EXTRA_SYSTEM = list()
        self.POLICIES_EXTRA_SYSTEM = list()
        self.POLICIES_EXTRA_CUSTOM = list()
        self.RULES_EXTRA_CUSTOM = list()
        self.RULES_EXTRA_SYSTEM = list()
        self.TAGS_EXTRA_CUSTOM = list()
        self.TAGS_EXTRA_SYSTEM = list()
        self.BLACKLIST_IP_EXTRA = list()
        self.BLACKLIST_HOSTS_EXTRA = list()
        self.FIREWALL_EXTRA = list()
        self.NEED_EXTRA_PROCESSING = self.args.DELETE_EXTRA_CUSTOM or self.args.DISABLE_EXTRA_CUSTOM \
                                     or self.args.DELETE_EXTRA_SYSTEM or self.args.DISABLE_EXTRA_CUSTOM

    def debug(self, s, indent=2):
        tabs = "    " * indent
        if self.args.DEBUG:
            print(tabs + "[.] {}".format(s))

    def log(self, s, indent=0):
        tabs = "    " * indent
        print(tabs + "[+] {}".format(s))

    def bootstrap(self):
        self.STORED_ACTIONS = self.mongo.fetch_all('actions')
        self.STORED_ALERTS = self.mongo.fetch_all('alerts')
        self.STORED_EVENTS = self.mongo.fetch_all('events')
        self.STORED_POLICIES = self.mongo.fetch_all('policies')
        self.STORED_RULES = self.mongo.fetch_all('rules')
        self.STORED_TAGS = self.mongo.fetch_all('tags')
        self.STORED_BLACKLIST_IP = self.mongo.fetch_all('blacklist.ip')
        self.STORED_BLACKLIST_HOSTS = self.mongo.fetch_all('blacklist.hosts')
        self.STORED_FIREWALL = self.mongo.fetch_all('ipset')

    def go_single(self):
        if self.args.CLASS == "actions":
            self.get_actions()
        elif self.args.CLASS == "alerts":
            (actions_from_alerts, events) = self.get_alerts()
            (rules, tags_from_events) = self.get_events(events)
            (actions_from_rules, tags_from_rules) = self.get_rules(rules)
            self.get_actions(actions_from_alerts + actions_from_rules)
            self.get_tags(tags_from_events + tags_from_rules)
        elif self.args.CLASS == "events":
            (rules, tags_from_events) = self.get_events()
            (actions, tags_from_rules) = self.get_rules(rules)
            self.get_actions(actions)
            self.get_tags(tags_from_events + tags_from_rules)
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
        elif self.args.CLASS == "blacklist-host":
            self.get_blacklist_hosts()
        elif self.args.CLASS == "firewall":
            actions = self.get_firewall()
            self.get_actions(actions)
        else:
            raise KeyError("Unknown class to import: {}".format(self.args.CLASS))

    def go_all(self):
        any_re = re.compile(".*", re.IGNORECASE)
        # Import all the actions
        self.args.CLASS = 'actions'
        self.args.IMPORT_ACTIONS = any_re
        self.go_single()

        # Import all the alerts
        self.args.CLASS = 'alerts'
        self.args.IMPORT_ALERTS = any_re
        self.go_single()

        # Import all the events
        self.args.CLASS = 'events'
        self.args.IMPORT_EVENTS = any_re
        self.go_single()

        # Import all the policies
        self.args.CLASS = 'policies'
        self.args.IMPORT_POLICIES = any_re
        self.go_single()

        # Import all the rules
        self.args.CLASS = 'rules'
        self.args.IMPORT_RULES = any_re
        self.go_single()

        # Import all the tags
        self.args.CLASS = 'tags'
        self.args.IMPORT_TAGS = any_re
        self.go_single()

        # Import all the blacklisted IPs
        self.args.CLASS = 'blacklist-ip'
        self.args.IMPORT_BLACKLIST = 'all'
        self.go_single()

        # Import all the blacklisted hosts
        self.args.CLASS = 'blacklist-host'
        self.go_single()

        # Import all the firewall rules
        self.args.CLASS = 'firewall'
        self.args.IMPORT_FIREWALL = 'all'
        self.go_single()

    def go(self):
        if self.args.CLASS == "all":
            self.go_all()
        else:
            self.go_single()

        if len(self.POLICIES) > 0:
            self.log("{} policies are eligible for import".format(len(self.POLICIES)), 1)
        if len(self.ACTIONS) > 0:
            self.log("{} actions are eligible for import".format(len(self.ACTIONS)), 1)
        if len(self.TAGS) > 0:
            self.log("{} tags are eligible for import".format(len(self.TAGS)), 1)
        if len(self.RULES) > 0:
            self.log("{} rules are eligible for import".format(len(self.RULES)), 1)
        if len(self.EVENTS) > 0:
            self.log("{} events are eligible for import".format(len(self.EVENTS)), 1)
        if len(self.ALERTS) > 0:
            self.log("{} alerts are eligible for import".format(len(self.ALERTS)), 1)
        if len(self.BLACKLIST_IP) > 0:
            self.log("{} blacklisted IP are eligible for import".format(len(self.BLACKLIST_IP)), 1)
        if len(self.BLACKLIST_HOSTS) > 0:
            self.log("{} blacklisted hostnames are eligible for import".format(len(self.BLACKLIST_HOSTS)), 1)
        if len(self.FIREWALL) > 0:
            self.log("{} firewalled IP are eligible for import".format(len(self.FIREWALL)), 1)

    # Methods to get data for import
    def get_actions(self, actions_to_check=None):
        def clean(obj):
            res = obj
            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.IMPORT_ACTIONS) == bool:  # Simple condition
                    if self.args.IMPORT_ACTIONS:  # Import all needed, confirm matching
                        return True
                    else:  # Do not import any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.IMPORT_ACTIONS) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.IMPORT_ACTIONS) == list:  # List of IDs
                if str(o['_id']) in self.args.IMPORT_ACTIONS:
                    return True
            else:  # Regex of name
                if self.args.IMPORT_ACTIONS.match(o['name'].encode('utf-8')):
                    return True

            return False

        # Fulfill the list of candidates
        res = list()
        if actions_to_check is None:  # Primary class, check all the objects
            for o in self.LOADED_ACTIONS:
                if matched(o):
                    res.append(clean(o))
        else:  # Dependent class, check only objects from received list
            for oid in actions_to_check:
                try:
                    action_id = ObjectId(oid)
                except InvalidId:
                    print("[!] Action ID {} is invalid, ignoring".format(oid))
                    continue
                for o in self.LOADED_ACTIONS:
                    if o["_id"] == action_id:
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)

        # Process the list of candidates and extract dependencies (if any)
        for o in res:
            if o not in self.ACTIONS:
                # Actions have no dependent classes, so just add object to the list for import
                self.ACTIONS.append(o)

    def get_alerts(self, alerts_to_check=None):
        def clean(obj):
            res = obj
            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.IMPORT_ALERTS) == bool:  # Simple condition
                    if self.args.IMPORT_ALERTS:  # Import all needed, confirm matching
                        return True
                    else:  # Do not import any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.IMPORT_ALERTS) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.IMPORT_ALERTS) == list:  # List of IDs
                if str(o['_id']) in self.args.IMPORT_ALERTS:
                    return True
            else:  # Regex of name
                if self.args.IMPORT_ALERTS.match(o['name'].encode('utf-8')):
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
            for o in self.LOADED_ALERTS:
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
                for o in self.LOADED_ALERTS:
                    if o["_id"] == alert_id:
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)
                                parent_alerts |= get_parent(o)

        # Recursively append parent alerts to the list of candidates
        while parent_alerts:
            oid = parent_alerts.pop()
            for o in self.LOADED_ALERTS:
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
                if type(self.args.IMPORT_EVENTS) == bool:  # Simple condition
                    if self.args.IMPORT_EVENTS:  # Import all needed, confirm matching
                        return True
                    else:  # Do not import any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.IMPORT_EVENTS) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.IMPORT_EVENTS) == list:  # List of IDs
                if str(o['_id']) in self.args.IMPORT_EVENTS:
                    return True
            else:  # Regex of name
                if self.args.IMPORT_EVENTS.match(o['name'].encode('utf-8')):
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
                        for r in self.LOADED_RULES:
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
                        for t in self.LOADED_TAGS:
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
            for o in self.LOADED_EVENTS:
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
                for o in self.LOADED_EVENTS:
                    if o["_id"] == event_id:
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)
                                parent_events |= get_parent(o)

        # Recursively append parent alerts to the list of candidates
        while parent_events:
            oid = parent_events.pop()
            for o in self.LOADED_EVENTS:
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
                          "SessionCookieProtector", "SQLiProtector", "WafJsProtector", "XMLProtector",
                          "XSSProtector"]
            wafjs_modules = ["botdetector", "domauth", "domcleaner", "domdetective"]
            res = obj
            if not self.args.IMPORT_EXCLUDES:
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

            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.IMPORT_POLICIES) == bool:  # Simple condition
                    if self.args.IMPORT_POLICIES:  # Import all needed, confirm matching
                        return True
                    else:  # Do not import any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.IMPORT_POLICIES) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.IMPORT_POLICIES) == list:  # List of IDs
                if str(o['_id']) in self.args.IMPORT_POLICIES:
                    return True
            else:  # Regex of name
                if self.args.IMPORT_POLICIES.match(o['name'].encode('utf-8')):
                    return True

            return False

        def get_dependent(o):
            rules = set()
            for r in self.LOADED_RULES:
                if 'policies' in r.keys() and r['policies']:
                    if o['_id'] in r['policies']:
                        rules.add(r['_id'])

            return rules

        # Fulfill the list of candidates
        res = list()
        if policies_to_check is None:  # Primary class,check all the objects
            for o in self.LOADED_POLICIES:
                if matched(o):
                    res.append(clean(o))
        else:  # Dependent class, check only objects from received list
            for oid in policies_to_check:
                for o in self.LOADED_POLICIES:
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
            policies = list()
            custom_policies = list()
            # Leave only importing policies
            for policy in res['policies']:
                for importing_policy in self.POLICIES:
                    if importing_policy['_id'] == policy:
                        policies.append(policy)
                        break
            for rec in res['custom_policies']:
                for importing_policy in self.POLICIES:
                    if importing_policy['_id'] == rec['policy']:
                        custom_policies.append(rec)
                        break
            res['custom_policies'] = custom_policies
            res['policies'] = policies
            if not self.args.IMPORT_EXCLUDES:
                res['filters'] = list()
            return res

        def matched(o, dependent=False):
            if dependent:  # Process dependent objects
                if type(self.args.IMPORT_RULES) == bool:  # Simple condition
                    if self.args.IMPORT_RULES:  # Import all needed, confirm matching
                        return True
                    else:  # Do not import any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.IMPORT_RULES) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.IMPORT_RULES) == list:  # List of IDs
                if str(o['_id']) in self.args.IMPORT_RULES:
                    return True
            else:  # Regex of name
                if self.args.IMPORT_RULES.match(o['name'].encode('utf-8')):
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
            if "custom_policies" in o.keys():
                for rec in o["custom_policies"]:
                    for p in self.POLICIES:
                        if rec['policy'] == p['_id']:
                            for a in rec['actions']:
                                actions.add(str(a))
                            break

            return actions, tags

        # Fulfill the list of candidates
        res = list()
        if rules_to_check is None:  # Primary class,check all the objects
            for o in self.LOADED_RULES:
                if matched(o):
                    res.append(clean(o))
        else:  # Dependent class, check only objects from received list
            for oid in rules_to_check:
                try:
                    rule_id = ObjectId(oid)
                except InvalidId:
                    print("[!] Action ID {} is invalid, ignoring".format(oid))
                    continue
                for o in self.LOADED_RULES:
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
                if type(self.args.IMPORT_TAGS) == bool:  # Simple condition
                    if self.args.IMPORT_TAGS:  # Import all needed, confirm matching
                        return True
                    else:  # Do not import any, decline matching
                        return False
            else:  # Process as primary class
                if type(self.args.IMPORT_TAGS) == bool:  # Simple condition means this class should be dependent
                    return False

            # Process complex conditions
            if type(self.args.IMPORT_TAGS) == list:  # List of IDs
                if str(o['_id']) in self.args.IMPORT_TAGS:
                    return True
            else:  # Regex of name
                if self.args.IMPORT_TAGS.match(o['name'].encode("utf-8")):
                    return True

            return False

        # Fulfill the list of candidates
        res = list()
        if tags_to_check is None:  # Primary class, check all the objects
            for o in self.LOADED_TAGS:
                if matched(o):
                    res.append(clean(o))
        else:  # Dependent class, check only objects from received list
            for oid in tags_to_check:
                try:
                    tag_id = ObjectId(oid)
                except InvalidId:
                    print("[!] Tag ID {} is invalid, ignoring".format(oid))
                    continue
                for o in self.LOADED_TAGS:
                    if o["_id"] == tag_id:
                        if matched(o, dependent=True):
                            if o not in res:
                                res.append(o)

        # Process the list of candidates and extract dependencies (if any)
        for o in res:
            if o not in self.TAGS:
                # Tags have no dependent classes, so just add object to the list for import
                self.TAGS.append(o)

    def get_blacklist_ip(self):
        def clean(obj):
            res = obj
            return res

        def matched(o):
            if self.args.IMPORT_BLACKLIST == 'all':  # Import all the records
                return True
            else:  # Import only exact type
                if self.args.IMPORT_BLACKLIST == 'vpn':
                    return o['type'] == 'VPN'
                elif self.args.IMPORT_BLACKLIST == 'proxy':
                    return o['type'] == 'Anonymous'
                elif self.args.IMPORT_BLACKLIST == 'tor':
                    return o['type'] == 'TOR'
                elif self.args.IMPORT_BLACKLIST == 'custom':
                    return o['type'] == 'Custom'

            return False

        # Fulfill the list of candidates
        res = list()
        for o in self.LOADED_BLACKLIST_IP:
            if matched(o):
                res.append(clean(o))

        # Process the list of candidates and extract dependencies (if any)
        for o in res:
            if o not in self.BLACKLIST_IP:
                # Blacklist IPs have no dependent classes, so just add object to the list for import
                self.BLACKLIST_IP.append(o)

    def get_blacklist_hosts(self):
        def clean(obj):
            res = obj
            return res

        def matched(o):
            # Always import all the blacklist hosts
            return True

        # Fulfill the list of candidates
        res = list()
        for o in self.LOADED_BLACKLIST_HOSTS:
            if matched(o):
                res.append(clean(o))

        # Process the list of candidates and extract dependencies (if any)
        for o in res:
            if o not in self.BLACKLIST_HOSTS:
                # Blacklist hosts have no dependent classes, so just add object to the list for import
                self.BLACKLIST_HOSTS.append(o)

    def get_firewall(self):
        def clean(obj):
            res = obj
            return res

        def matched(o):
            if self.args.IMPORT_FIREWALL == 'all':  # Import all the records
                return True
            else:  # Import only exact class
                return self.args.IMPORT_FIREWALL == o['tag']

        def get_dependent(o):
            actions = set()
            if "action_oid" in o.keys():
                actions.add(o['action_oid'])

            return actions

        # Fulfill the list of candidates
        res = list()
        for o in self.LOADED_FIREWALL:
            if matched(o):
                res.append(clean(o))

        # Process the list of candidates and extract dependencies (if any)
        dependent_actions = set()
        for o in res:
            if o not in self.FIREWALL:
                self.FIREWALL.append(o)
                dependent_actions |= get_dependent(o)

        return list(dependent_actions)

    # Methods to load data
    def load_tags(self, form="yaml"):
        counter = 0
        load_path = os.path.join(self.args.FOLDER, self.TAGS_DIR)
        if form == "yaml":
            if os.path.exists(load_path):
                for filename in os.listdir(load_path):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        self.debug("Processing file {}".format(os.path.join(load_path, filename)))
                        self.LOADED_TAGS.append(load_from_yaml(os.path.join(load_path, filename)))
                        counter += 1
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

        return counter

    def load_policies(self, form="yaml"):
        counter = 0
        load_path = os.path.join(self.args.FOLDER, self.POLICIES_DIR)
        if form == "yaml":
            if os.path.exists(load_path):
                for filename in os.listdir(load_path):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        self.debug("Processing file {}".format(os.path.join(load_path, filename)))
                        self.LOADED_POLICIES.append(load_from_yaml(os.path.join(load_path, filename)))
                        counter += 1
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

        return counter

    def load_rules(self, form="yaml"):
        counter = 0
        load_path = os.path.join(self.args.FOLDER, self.RULES_DIR)
        if form == "yaml":
            if os.path.exists(load_path):
                for filename in os.listdir(load_path):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        self.debug("Processing file {}".format(os.path.join(load_path, filename)))
                        self.LOADED_RULES.append(load_from_yaml(os.path.join(load_path, filename)))
                        counter += 1
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

        return counter

    def load_events(self, form="yaml"):
        counter = 0
        load_path = os.path.join(self.args.FOLDER, self.EVENTS_DIR)
        if form == "yaml":
            if os.path.exists(load_path):
                for filename in os.listdir(load_path):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        self.debug("Processing file {}".format(os.path.join(load_path, filename)))
                        self.LOADED_EVENTS.append(load_from_yaml(os.path.join(load_path, filename)))
                        counter += 1
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

        return counter

    def load_alerts(self, form="yaml"):
        counter = 0
        load_path = os.path.join(self.args.FOLDER, self.ALERTS_DIR)
        if form == "yaml":
            if os.path.exists(load_path):
                for filename in os.listdir(load_path):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        self.debug("Processing file {}".format(os.path.join(load_path, filename)))
                        self.LOADED_ALERTS.append(load_from_yaml(os.path.join(load_path, filename)))
                        counter += 1
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

        return counter

    def load_actions(self, form="yaml"):
        counter = 0
        load_path = os.path.join(self.args.FOLDER, self.ACTIONS_DIR)
        if form == "yaml":
            if os.path.exists(load_path):
                for filename in os.listdir(load_path):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        self.debug("Processing file {}".format(os.path.join(load_path, filename)))
                        self.LOADED_ACTIONS.append(load_from_yaml(os.path.join(load_path, filename)))
                        counter += 1
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

        return counter

    def load_blacklist_ip(self, form="yaml"):
        counter = 0
        load_path = os.path.join(self.args.FOLDER, self.BLACKLIST_IP_DIR)
        if form == "yaml":
            if os.path.exists(load_path):
                for filename in os.listdir(load_path):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        self.debug("Processing file {}".format(os.path.join(load_path, filename)))
                        self.LOADED_BLACKLIST_IP.append(load_from_yaml(os.path.join(load_path, filename)))
                        counter += 1
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

        return counter

    def load_blacklist_hosts(self, form="yaml"):
        counter = 0
        load_path = os.path.join(self.args.FOLDER, self.BLACKLIST_HOSTS_DIR)
        if form == "yaml":
            if os.path.exists(load_path):
                for filename in os.listdir(load_path):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        self.debug("Processing file {}".format(os.path.join(load_path, filename)))
                        self.LOADED_BLACKLIST_HOSTS.append(load_from_yaml(os.path.join(load_path, filename)))
                        counter += 1
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

        return counter

    def load_firewall(self, form="yaml"):
        counter = 0
        load_path = os.path.join(self.args.FOLDER, self.FIREWALL_DIR)
        if form == "yaml":
            if os.path.exists(load_path):
                for filename in os.listdir(load_path):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        self.debug("Processing file {}".format(os.path.join(load_path, filename)))
                        self.LOADED_FIREWALL.append(load_from_yaml(os.path.join(load_path, filename)))
                        counter += 1
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

        return counter

    def load(self, form="yaml"):
        loaded_count = self.load_policies(form)
        if loaded_count > 0:
            self.log("Loaded {} policies from files".format(loaded_count), 1)
        loaded_count = self.load_actions(form)
        if loaded_count > 0:
            self.log("Loaded {} actions from files".format(loaded_count), 1)
        loaded_count = self.load_tags(form)
        if loaded_count > 0:
            self.log("Loaded {} tags from files".format(loaded_count), 1)
        loaded_count = self.load_rules(form)
        if loaded_count > 0:
            self.log("Loaded {} rules from files".format(loaded_count), 1)
        loaded_count = self.load_events(form)
        if loaded_count > 0:
            self.log("Loaded {} events from files".format(loaded_count), 1)
        loaded_count = self.load_alerts(form)
        if loaded_count > 0:
            self.log("Loaded {} alerts from files".format(loaded_count), 1)
        loaded_count = self.load_blacklist_ip(form)
        if loaded_count > 0:
            self.log("Loaded {} blacklisted IP from files".format(loaded_count), 1)
        loaded_count = self.load_blacklist_hosts(form)
        if loaded_count > 0:
            self.log("Loaded {} blacklisted hostnames from files".format(loaded_count), 1)
        loaded_count = self.load_firewall(form)
        if loaded_count > 0:
            self.log("Loaded {} firewalled IP from files".format(loaded_count), 1)

    # Methods for DB update
    def commit(self):
        updated_count = self.commit_policies()
        if updated_count > 0:
            self.log("Updated {} policies".format(updated_count), 1)
        updated_count = self.commit_actions()
        if updated_count > 0:
            self.log("Updated {} actions".format(updated_count), 1)
        updated_count = self.commit_tags()
        if updated_count > 0:
            self.log("Updated {} tags".format(updated_count), 1)
        updated_count = self.commit_rules()
        if updated_count > 0:
            self.log("Updated {} rules".format(updated_count), 1)
        updated_count = self.commit_events()
        if updated_count > 0:
            self.log("Updated {} events".format(updated_count), 1)
        updated_count = self.commit_alerts()
        if updated_count > 0:
            self.log("Updated {} alerts".format(updated_count), 1)
        updated_count = self.commit_blacklist_ip()
        if updated_count > 0:
            self.log("Updated {} balcklisted IP".format(updated_count), 1)
        updated_count = self.commit_blacklist_hosts()
        if updated_count > 0:
            self.log("Updated {} blacklisted hostnames".format(updated_count), 1)
        updated_count = self.commit_firewall()
        if updated_count > 0:
            self.log("Updated {} firewalled IP".format(updated_count), 1)

    def commit_actions(self):
        def clear(obj):
            res = deepcopy(obj)
            return res

        def replace_one(o):
            self.mongo.replace_one('actions', str(o['_id']), o)

        def is_newer(stored, loaded):
            if "last_modified" in stored.keys():  # Stored object is crafted or was modified manually
                if "last_modified" in loaded.keys():  # Loaded object is crafted or was modified manually
                    return loaded['last_modified'] > stored['last_modified']
                else:  # Loaded object wasn't modified
                    return False
            else:  # Stored object is from-the-box and wasn't modified manually
                if "last_modified" in loaded.keys():  # Loaded object was modified manually
                    return True
                else:  # Compare revisions
                    return loaded['revision'] > stored['revision']

        counter = 0
        for loaded in self.ACTIONS:
            self.debug("Updating action {}".format(str(loaded['_id'])))
            clean_loaded = clear(loaded)
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(clean_loaded)
                counter += 1
            else:
                stored = {}
                for a in self.STORED_ACTIONS:
                    if a['_id'] == loaded["_id"]:
                        stored = a
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(clean_loaded)
                        counter += 1
                else:
                    replace_one(clean_loaded)
                    counter += 1

        return counter

    def commit_alerts(self):
        def clear(obj):
            res = deepcopy(obj)
            return res

        def replace_one(o):
            self.mongo.replace_one('alerts', str(o['_id']), o)

        def is_newer(stored, loaded):
            if "last_modified" in stored.keys():  # Stored object is crafted or was modified manually
                if "last_modified" in loaded.keys():  # Loaded object is crafted or was modified manually
                    return loaded['last_modified'] > stored['last_modified']
                else:  # Loaded object wasn't modified
                    return False
            else:  # Stored object is from-the-box and wasn't modified manually
                if "last_modified" in loaded.keys():  # Loaded object was modified manually
                    return True
                else:  # Compare revisions
                    return loaded['revision'] > stored['revision']

        counter = 0
        for loaded in self.ALERTS:
            self.debug("Updating alert {}".format(str(loaded['_id'])))
            clean_loaded = clear(loaded)
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(clean_loaded)
                counter += 1
            else:
                stored = {}
                for a in self.STORED_ALERTS:
                    if a['_id'] == loaded["_id"]:
                        stored = a
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(clean_loaded)
                        counter += 1
                else:
                    replace_one(clean_loaded)
                    counter += 1

        return counter

    def commit_events(self):
        def clear(obj):
            res = deepcopy(obj)
            return res

        def replace_one(o):
            self.mongo.replace_one('events', str(o['_id']), o)

        def is_newer(stored, loaded):
            if "last_modified" in stored.keys():  # Stored object is crafted or was modified manually
                if "last_modified" in loaded.keys():  # Loaded object is crafted or was modified manually
                    return loaded['last_modified'] > stored['last_modified']
                else:  # Loaded object wasn't modified
                    return False
            else:  # Stored object is from-the-box and wasn't modified manually
                if "last_modified" in loaded.keys():  # Loaded object was modified manually
                    return True
                else:  # Compare revisions
                    return loaded['revision'] > stored['revision']

        counter = 0
        for loaded in self.EVENTS:
            self.debug("Updating event {}".format(str(loaded['_id'])))
            clean_loaded = clear(loaded)
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(clean_loaded)
                counter += 1
            else:
                stored = {}
                for e in self.STORED_EVENTS:
                    if e['_id'] == loaded["_id"]:
                        stored = e
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(clean_loaded)
                        counter += 1
                else:
                    replace_one(clean_loaded)
                    counter += 1

        return counter

    def commit_policies(self):
        def clear(obj):
            protectors = ["AuthLDAP", "AuthOracle", "BlacklistProtector", "CSPProtector",
                          "CSRFProtector", "DDoSProtector", "HMMProtector", "HTTPProtector",
                          "ICAPProtector", "JSONProtector", "OpenRedirectProtector", "ResponseFilter",
                          "RobotProtector", "RuleEngine", "RVPProtector", "ScriptEngine",
                          "SessionCookieProtector", "SQLiProtector", "WafJsProtector", "XMLProtector",
                          "XSSProtector"]
            wafjs_modules = ["botdetector", "domauth", "domcleaner", "domdetective"]
            res = obj
            if not self.args.IMPORT_EXCLUDES:
                # Clear policy filter
                res['filters'] = list()
                # Clear protectors' filters
                for p in protectors:
                    if p in res.keys() and res[p]:
                        if 'filters' in res[p].keys():
                            res[p]['filters'] = list()
                # Clear filters for WafJs modules
                for m in wafjs_modules:
                    if 'filters' in res["WafJsProtector"][m].keys():
                        res["WafJsProtector"][m]['filters'] = list()

            return res

        def build_update(loaded, stored):
            tmp = deepcopy(loaded)
            protectors = ["AuthLDAP", "AuthOracle", "BlacklistProtector", "CSPProtector",
                          "CSRFProtector", "DDoSProtector", "HMMProtector", "HTTPProtector",
                          "ICAPProtector", "JSONProtector", "OpenRedirectProtector", "ResponseFilter",
                          "RobotProtector", "RuleEngine", "RVPProtector", "ScriptEngine",
                          "SessionCookieProtector", "SQLiProtector", "XMLProtector",
                          "XSSProtector"]
            wafjs_modules = ["botdetector", "domauth", "domcleaner", "domdetective"]

            res = {"$set": {}}
            if not self.args.IMPORT_EXCLUDES:  # Keep filters
                # Keep policy filter
                tmp['filters'] = deepcopy(stored['filters'])
                # keep protectors' filters
                for p in protectors:
                    if 'filters' in stored[p].keys():
                        tmp[p]['filters'] = deepcopy(stored[p]['filters'])
                # Keep filters for WafJs modules
                for m in wafjs_modules:
                    if 'filters' in stored["WafJsProtector"][m].keys():
                        tmp["WafJsProtector"][m]['filters'] = deepcopy(stored["WafJsProtector"][m]['filters'])

            res["$set"] = tmp

            return res

        def replace_one(o):
            self.mongo.replace_one('policies', str(o['_id']), o)

        def update_one(loaded, stored):
            self.mongo.update_one('policies', str(loaded['_id']), build_update(loaded, stored))

        def is_newer(stored, loaded):
            return True  # Always update policies

        counter = 0
        for loaded in self.POLICIES:
            self.debug("Updating policy {}".format(str(loaded['_id'])))
            clean_loaded = clear(loaded)
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(clean_loaded)
                counter += 1
            else:
                stored = {}
                for t in self.STORED_POLICIES:
                    if t['_id'] == loaded["_id"]:
                        stored = t
                        break
                if stored:
                    if is_newer(stored, loaded):
                        update_one(clean_loaded, stored)
                        counter += 1
                else:
                    replace_one(clean_loaded)
                    counter += 1

        return counter

    def commit_rules(self):
        def clear(obj):
            res = deepcopy(obj)
            res['template_id'] = list()
            policies = list()
            custom_policies = list()
            filters = list()
            # Keep only importing policies
            for policy in res['policies']:
                for importing_policy in self.POLICIES:
                    if importing_policy['_id'] == policy:
                        policies.append(policy)
                        break
            # Keep only custom actions for importing policies
            for rec in res['custom_policies']:
                for importing_policy in self.POLICIES:
                    if importing_policy['_id'] == rec['policy']:
                        custom_policies.append(rec)
                        break
            # Keep only filters for importing policies
            for f in res['filters']:
                is_by_policy_filter = False
                if 'expr' in f.keys() and f['expr']:
                    if 'and' in f['expr'].keys() and f['expr']['and']:
                        if f['expr']['and'][0]['operator'] == '=':
                            if 'variables' in f['expr']['and'][0].keys() and f['expr']['and'][0]['variables']:
                                if f['expr']['and'][0]['variables'][0][
                                    'name'] == 'POLICY_ID':  # Filter for exact policy
                                    is_by_policy_filter = True
                                    filter_policy_id = f['expr']['and'][0]['value']
                                    for importing_policy in self.POLICIES:
                                        if str(importing_policy['_id']) == filter_policy_id:
                                            filters.append(f)
                                            break
                if not is_by_policy_filter:  # Not a by-policy filter, keep it
                    filters.append(f)

            res['custom_policies'] = custom_policies
            res['policies'] = policies
            if not self.args.IMPORT_EXCLUDES:  # Clear excludes
                res['filters'] = list()
            else:
                res['filters'] = filters
            return res

        def build_update(loaded, stored):
            tmp = deepcopy(loaded)
            res = {"$set": {}}

            if not self.args.IMPORT_EXCLUDES:  # Keep excludes
                if "filters" in tmp.keys():
                    tmp['filters'] = deepcopy(stored['filters'])

            if "policies" in tmp.keys():  # Keep update policies
                tmp['policies'] = deepcopy(stored['policies'])

            if "custom_policies" in tmp.keys():  # Keep custom policy actions
                tmp['custom_policies'] = deepcopy(stored['custom_policies'])

            tags = deepcopy(stored["tags"])
            if "tags" in tmp.keys() and tmp['tags']:  # Join new tags with stored ones
                for t in tmp["tags"]:
                    if t not in tags:
                        tags.append(t)
            tmp["tags"] = tags

            res["$set"] = tmp
            return res

        def replace_one(o):
            self.mongo.replace_one('rules', str(o['_id']), o)

        def update_one(loaded, stored):
            self.mongo.update_one('rules', str(loaded['_id']), build_update(loaded, stored))

        def is_newer(stored, loaded):
            return True  # Always update rule

        counter = 0
        for loaded in self.RULES:
            self.debug("Updating rule {}".format(str(loaded['_id'])))
            clean_loaded = clear(loaded)
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(clean_loaded)
                counter += 1
            else:
                stored = {}
                for t in self.STORED_RULES:
                    if t['_id'] == loaded["_id"]:
                        stored = t
                        break
                if stored:
                    if is_newer(stored, loaded):
                        update_one(clean_loaded, stored)
                        counter += 1
                else:
                    replace_one(clean_loaded)
                    counter += 1

        return counter

    def commit_tags(self):
        def clear(obj):
            res = deepcopy(obj)
            return res

        def replace_one(o):
            self.mongo.replace_one('tags', str(o['_id']), o)

        def is_newer(stored, loaded):
            if "last_modified" in stored.keys():  # Stored object is crafted or was modified manually
                if "last_modified" in loaded.keys():  # Loaded object is crafted or was modified manually
                    return loaded['last_modified'] > stored['last_modified']
                else:  # Loaded object wasn't modified
                    return False
            else:  # Stored object is from-the-box and wasn't modified manually
                if "last_modified" in loaded.keys():  # Loaded object was modified manually
                    return True
                else:  # Compare revisions
                    return loaded['revision'] > stored['revision']

        counter = 0
        for loaded in self.TAGS:
            self.debug("Updating tag {}".format(str(loaded['_id'])))
            clean_loaded = clear(loaded)
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(clean_loaded)
                counter += 1
            else:
                stored = {}
                for t in self.STORED_TAGS:
                    if t['_id'] == loaded["_id"]:
                        stored = t
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(clean_loaded)
                        counter += 1
                else:
                    replace_one(clean_loaded)
                    counter += 1

        return counter

    def commit_blacklist_ip(self):
        def clear(obj):
            res = deepcopy(obj)
            return res

        def replace_one(o):
            self.mongo.replace_one('blacklist.ip', str(o['_id']), o)

        def is_newer(stored, loaded):
            return loaded['last_modified'] > stored['last_modified']

        counter = 0
        for loaded in self.BLACKLIST_IP:
            self.debug("Updating blacklisted IP {}".format(str(loaded['_id'])))
            clean_loaded = clear(loaded)
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(clean_loaded)
                counter += 1
            else:
                stored = {}
                for i in self.STORED_BLACKLIST_IP:
                    if i['_id'] == loaded["_id"]:
                        stored = i
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(clean_loaded)
                        counter += 1
                else:
                    replace_one(clean_loaded)
                    counter += 1

        return counter

    def commit_blacklist_hosts(self):
        def clear(obj):
            res = deepcopy(obj)
            return res

        def replace_one(o):
            self.mongo.replace_one('blacklist.hosts', str(o['_id']), o)

        def is_newer(stored, loaded):
            if "last_modified" in stored.keys():  # Stored object is crafted or was modified manually
                if "last_modified" in loaded.keys():  # Loaded object is crafted or was modified manually
                    return loaded['last_modified'] > stored['last_modified']
                else:  # Loaded object wasn't modified
                    return False
            else:  # Stored object is from-the-box and wasn't modified manually
                if "last_modified" in loaded.keys():  # Loaded object was modified manually
                    return True
                else:  # Both objects are from-the-box
                    return False

        counter = 0
        for loaded in self.BLACKLIST_HOSTS:
            self.debug("Updating blacklisted hostname {}".format(str(loaded['_id'])))
            clean_loaded = clear(loaded)
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(clean_loaded)
                counter += 1
            else:
                stored = {}
                for h in self.STORED_BLACKLIST_HOSTS:
                    if h['_id'] == loaded["_id"]:
                        stored = h
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(clean_loaded)
                        counter += 1
                else:
                    replace_one(clean_loaded)
                    counter += 1

        return counter

    def commit_firewall(self):
        def clear(obj):
            res = deepcopy(obj)
            return res

        def replace_one(o):
            self.mongo.replace_one('ipset', str(o['_id']), o)

        def is_newer(stored, loaded):
            return loaded['last_modified'] > stored['last_modified']

        counter = 0
        for loaded in self.FIREWALL:
            self.debug("Updating firewalled IP {}".format(str(loaded['_id'])))
            clean_loaded = clear(loaded)
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(clean_loaded)
                counter += 1
            else:
                stored = {}
                for r in self.FIREWALL:
                    if r['_id'] == loaded["_id"]:
                        stored = r
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(clean_loaded)
                        counter += 1
                else:
                    replace_one(clean_loaded)
                    counter += 1

        return counter

    # Methods to get extra objects (exist in MongoDB and absent in files)
    def get_extra(self):
        extra_count = self.get_extra_policies()
        if extra_count > 0:
            self.log("Got {} extra policies: {} system, {} custom".format(extra_count, len(self.POLICIES_EXTRA_SYSTEM),
                                                                          len(self.POLICIES_EXTRA_CUSTOM)), 1)
        extra_count = self.get_extra_actions()
        if extra_count > 0:
            self.log("Got {} extra actions: {} system, {} custom".format(extra_count, len(self.ACTIONS_EXTRA_SYSTEM),
                                                                         len(self.ACTIONS_EXTRA_CUSTOM)), 1)
        extra_count = self.get_extra_tags()
        if extra_count > 0:
            self.log("Got {} extra tags: {} system, {} custom".format(extra_count, len(self.TAGS_EXTRA_SYSTEM),
                                                                      len(self.TAGS_EXTRA_CUSTOM)), 1)
        extra_count = self.get_extra_rules()
        if extra_count > 0:
            self.log("Got {} extra rules: {} system, {} custom".format(extra_count, len(self.RULES_EXTRA_SYSTEM),
                                                                       len(self.RULES_EXTRA_CUSTOM)), 1)
        extra_count = self.get_extra_events()
        if extra_count > 0:
            self.log("Got {} extra events: {} system, {} custom".format(extra_count, len(self.EVENTS_EXTRA_SYSTEM),
                                                                        len(self.EVENTS_EXTRA_CUSTOM)), 1)
        extra_count = self.get_extra_alerts()
        if extra_count > 0:
            self.log("Got {} extra alerts: {} system, {} custom".format(extra_count, len(self.ALERTS_EXTRA_SYSTEM),
                                                                        len(self.ALERTS_EXTRA_CUSTOM)), 1)
        extra_count = self.get_extra_blacklist_ip()
        if extra_count > 0:
            self.log("Got {} extra blacklisted IP".format(extra_count), 1)
        extra_count = self.get_extra_blacklist_hosts()
        if extra_count > 0:
            self.log("Got {} extra blacklisted hosts".format(extra_count), 1)
        extra_count = self.get_extra_firewall()
        if extra_count > 0:
            self.log("Got {} extra firewalled IP".format(extra_count), 1)

    def get_extra_policies(self):
        res = list()
        for stored in self.STORED_POLICIES:
            found = False
            for loaded in self.LOADED_POLICIES:
                if str(stored['_id']) == str(loaded['_id']):
                    found = True
                    break
            if not found:
                res.append(stored)
                self.debug("Policy {} counted as extra".format(str(stored['_id'])))

        for o in res:
            if '_is_system' in o.keys() and not o['_is_system'] is None and o['_is_system']:
                self.POLICIES_EXTRA_SYSTEM.append(str(o['_id']))
            else:
                self.POLICIES_EXTRA_CUSTOM.append(str(o['_id']))

        return len(res)

    def get_extra_actions(self):
        res = list()
        for stored in self.STORED_ACTIONS:
            found = False
            for loaded in self.LOADED_ACTIONS:
                if str(stored['_id']) == str(loaded['_id']):
                    found = True
                    break
            if not found:
                res.append(stored)
                self.debug("Action {} counted as extra".format(str(stored['_id'])))

        for o in res:
            if '_is_system' in o.keys() and not o['_is_system'] is None and o['_is_system']:
                self.ACTIONS_EXTRA_SYSTEM.append(str(o['_id']))
            else:
                self.ACTIONS_EXTRA_CUSTOM.append(str(o['_id']))

        return len(res)

    def get_extra_tags(self):
        res = list()
        for stored in self.STORED_TAGS:
            found = False
            for loaded in self.LOADED_TAGS:
                if str(stored['_id']) == str(loaded['_id']):
                    found = True
                    break
            if not found:
                res.append(stored)
                self.debug("Tag {} counted as extra".format(str(stored['_id'])))

        for o in res:
            if '_is_system' in o.keys() and not o['_is_system'] is None and o['_is_system']:
                self.TAGS_EXTRA_SYSTEM.append(str(o['_id']))
            else:
                self.TAGS_EXTRA_CUSTOM.append(str(o['_id']))

        return len(res)

    def get_extra_rules(self):
        res = list()
        for stored in self.STORED_RULES:
            found = False
            for loaded in self.LOADED_RULES:
                if str(stored['_id']) == str(loaded['_id']):
                    found = True
                    break
            if not found:
                res.append(stored)
                self.debug("Rule {} counted as extra".format(str(stored['_id'])))

        for o in res:
            if '_is_system' in o.keys() and not o['_is_system'] is None and o['_is_system']:
                self.RULES_EXTRA_SYSTEM.append(str(o['_id']))
            else:
                self.RULES_EXTRA_CUSTOM.append(str(o['_id']))

        return len(res)

    def get_extra_events(self):
        res = list()
        for stored in self.STORED_EVENTS:
            found = False
            for loaded in self.LOADED_EVENTS:
                if str(stored['_id']) == str(loaded['_id']):
                    found = True
                    break
            if not found:
                res.append(stored)
                self.debug("Event {} counted as extra".format(str(stored['_id'])))

        for o in res:
            if '_is_system' in o.keys() and not o['_is_system'] is None and o['_is_system']:
                self.EVENTS_EXTRA_SYSTEM.append(str(o['_id']))
            else:
                self.EVENTS_EXTRA_CUSTOM.append(str(o['_id']))

        return len(res)

    def get_extra_alerts(self):
        res = list()
        for stored in self.STORED_ALERTS:
            found = False
            for loaded in self.LOADED_ALERTS:
                if str(stored['_id']) == str(loaded['_id']):
                    found = True
                    break
            if not found:
                res.append(stored)
                self.debug("Alert {} counted as extra".format(str(stored['_id'])))

        for o in res:
            if '_is_system' in o.keys() and not o['_is_system'] is None and o['_is_system']:
                self.ALERTS_EXTRA_SYSTEM.append(str(o['_id']))
            else:
                self.ALERTS_EXTRA_CUSTOM.append(str(o['_id']))

        return len(res)

    def get_extra_blacklist_ip(self):
        res = list()
        for stored in self.STORED_BLACKLIST_IP:
            found = False
            for loaded in self.LOADED_BLACKLIST_IP:
                if str(stored['_id']) == str(loaded['_id']):
                    found = True
                    break
            if not found:
                res.append(stored)
                self.debug("Blacklisted IP {} counted as extra".format(str(stored['_id'])))

        for o in res:
            self.BLACKLIST_IP_EXTRA.append(str(o['_id']))

        return len(res)

    def get_extra_blacklist_hosts(self):
        res = list()
        for stored in self.STORED_BLACKLIST_HOSTS:
            found = False
            for loaded in self.LOADED_BLACKLIST_HOSTS:
                if str(stored['_id']) == str(loaded['_id']):
                    found = True
                    break
            if not found:
                res.append(stored)
                self.debug("Blacklisted host {} counted as extra".format(str(stored['_id'])))

        for o in res:
            self.BLACKLIST_HOSTS_EXTRA.append(str(o['_id']))

        return len(res)

    def get_extra_firewall(self):
        res = list()
        for stored in self.STORED_FIREWALL:
            found = False
            for loaded in self.LOADED_FIREWALL:
                if str(stored['_id']) == str(loaded['_id']):
                    found = True
                    break
            if not found:
                res.append(stored)
                self.debug("Firewalled IP {} counted as extra".format(str(stored['_id'])))

        for o in res:
            self.FIREWALL_EXTRA.append(str(o['_id']))

        return len(res)

    # Methods to get rid of extra objects
    def delete_system(self):
        self.log("Deleting system extra objects ...")
        deleted_total = 0

        deleted_count = 0
        for str_id in self.ALERTS_EXTRA_SYSTEM:
            self.debug("Deleting system alert {}".format(str_id))
            self.mongo.delete_one('alerts', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} system alerts".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.EVENTS_EXTRA_SYSTEM:
            self.debug("Deleting system event {}".format(str_id))
            self.mongo.delete_one('events', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} system events".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.RULES_EXTRA_SYSTEM:
            self.debug("Deleting system rule {}".format(str_id))
            self.mongo.delete_one('rules', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} system rules".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.TAGS_EXTRA_SYSTEM:
            self.debug("Deleting system tag {}".format(str_id))
            self.mongo.delete_one('tags', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} system tags".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.ACTIONS_EXTRA_SYSTEM:
            self.debug("Deleting system action {}".format(str_id))
            self.mongo.delete_one('actions', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} system actions".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.POLICIES_EXTRA_SYSTEM:
            self.debug("Deleting system policy {}".format(str_id))
            self.mongo.delete_one('policies', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} system policies".format(deleted_count), 1)
        deleted_total += deleted_count

        if deleted_total == 0:
            self.log("Nothing to delete", 1)

        self.log("DONE\n")

    def delete_custom(self):
        self.log("Deleting custom extra objects ...")
        deleted_total = 0

        deleted_count = 0
        for str_id in self.FIREWALL_EXTRA:
            self.debug("Deleting firewalled IP {}".format(str_id))
            self.mongo.delete_one('ipset', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} custom firewalled IP".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.BLACKLIST_HOSTS_EXTRA:
            self.debug("Deleting blacklisted host {}".format(str_id))
            self.mongo.delete_one('blacklist.hosts', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} custom blacklisted hosts".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.BLACKLIST_IP_EXTRA:
            self.debug("Deleting blacklisted IP {}".format(str_id))
            self.mongo.delete_one('blacklist.ip', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} custom blacklisted IP".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.ALERTS_EXTRA_CUSTOM:
            self.debug("Deleting custom alert {}".format(str_id))
            self.mongo.delete_one('alerts', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} custom alerts".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.EVENTS_EXTRA_CUSTOM:
            self.debug("Deleting custom event {}".format(str_id))
            self.mongo.delete_one('events', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} custom events".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.RULES_EXTRA_CUSTOM:
            self.debug("Deleting custom rule {}".format(str_id))
            self.mongo.delete_one('rules', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} custom rules".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.TAGS_EXTRA_CUSTOM:
            self.debug("Deleting custom tag {}".format(str_id))
            self.mongo.delete_one('tags', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} custom tags".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.ACTIONS_EXTRA_CUSTOM:
            self.debug("Deleting custom action {}".format(str_id))
            self.mongo.delete_one('actions', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} custom actions".format(deleted_count), 1)
        deleted_total += deleted_count

        deleted_count = 0
        for str_id in self.POLICIES_EXTRA_CUSTOM:
            self.debug("Deleting custom policy {}".format(str_id))
            self.mongo.delete_one('policies', str_id)
            deleted_count += 1
        if deleted_count > 0:
            self.log("Deleted {} custom policies".format(deleted_count), 1)
        deleted_total += deleted_count

        if deleted_total == 0:
            self.log("Nothing to delete", 1)

        self.log("DONE\n")

    def disable_system(self):
        self.log("Disabling system extra objects ...")
        disabled_total = 0

        disabled_count = 0
        for str_id in self.ALERTS_EXTRA_SYSTEM:
            self.debug("Disabling system alert {}".format(str_id))
            self.mongo.update_one('alerts', str_id, {'enabled': False})
            disabled_count += 1
        if disabled_count > 0:
            self.log("Disabled {} system alerts".format(disabled_count), 1)
        disabled_total += disabled_count

        disabled_count = 0
        for str_id in self.RULES_EXTRA_SYSTEM:
            self.debug("Disabling system rules {}".format(str_id))
            self.mongo.update_one('rules', str_id, {'enabled': False})
            disabled_count += 1
        if disabled_count > 0:
            self.log("Disabled {} system rules".format(disabled_count), 1)
        disabled_total += disabled_count

        if disabled_total == 0:
            self.log("Nothing to disable", 1)

        self.log("DONE\n")

    def disable_custom(self):
        self.log("Disabling custom extra objects ...")
        disabled_total = 0

        disabled_count = 0
        for str_id in self.ALERTS_EXTRA_CUSTOM:
            self.debug("Disabling custom alert {}".format(str_id))
            self.mongo.update_one('alerts', str_id, {'enabled': False})
            disabled_count += 1
        if disabled_count > 0:
            self.log("Disabled {} custom alerts".format(disabled_count), 1)
        disabled_total += disabled_count

        disabled_count = 0
        for str_id in self.RULES_EXTRA_CUSTOM:
            self.debug("Disabling custom rules {}".format(str_id))
            self.mongo.update_one('rules', str_id, {'enabled': False})
            disabled_count += 1
        if disabled_count > 0:
            self.log("Disabled {} custom rules".format(disabled_count), 1)
        disabled_total += disabled_count

        if disabled_total == 0:
            self.log("Nothing to disable", 1)

        self.log("DONE\n")


if __name__ == "__main__":
    r = Run(parse_cli_args(), MongoDB())
    r.bootstrap()

    # Load from files
    r.log("Loading ruleset from files ...")
    r.load()
    r.log("DONE\n")

    # Get data
    r.log("Making subset to import ...")
    r.go()
    r.log("DONE\n")

    # Commit data to storage
    r.log("Committing changes to MongoDB ...")
    r.commit()
    r.log("DONE\n")

    # Process extra objects if needed
    if r.NEED_EXTRA_PROCESSING:
        # Get extra objects
        r.log("Getting extra objects ...")
        r.get_extra()
        r.log("DONE\n")

        if r.args.DISABLE_EXTRA_SYSTEM:
            r.disable_system()
        if r.args.DISABLE_EXTRA_CUSTOM:
            r.disable_custom()
        if r.args.DELETE_EXTRA_SYSTEM:
            r.delete_system()
        if r.args.DELETE_EXTRA_CUSTOM:
            r.delete_custom()

    r.log("DONE. Import successfully completed.")
