import argparse
import re
import subprocess
from datetime import datetime
import os
import yaml
import sys
from pymongo import MongoClient
from bson import objectid, int64, ObjectId
from bson.errors import InvalidId


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
    parser.add_argument('MODE',
                        action='store',
                        choices=["all", "class"],
                        help='Mode of import. Use "all" to import all the supported classes, or "class" to import exact class of objects')
    parser.add_argument('-c', '--class',
                        action='store',
                        dest='CLASS',
                        choices=["policies", "rules", "tags", "events", "alerts", "actions"],
                        required=' class ' in sys.argv,
                        help='Class of object(s) to be imported. Other classes will be imported only if needed')
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
                        dest='BLACKLIST',
                        choices=["all", "proxy", "vpn", "tor", "custom"],
                        default='all',
                        required=False,
                        help='Type of blacklisted IP record to import. By default all records will be imported')
    parser.add_argument('--firewall',
                        action='store',
                        dest='FIREWALL',
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
        if self.args.MODE == "all":
            self.go_all()
        else:
            self.go_single()

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
            res = obj
            res['template_id'] = None
            if not self.args.IMPORT_EXCLUDES:
                res['filters'] = list()
                for p in protectors:
                    if p in res.keys() and res[p]:
                        if 'filters' in res[p].keys():
                            res[p]['filters'] = list()

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
            if rules_to_check is None:  # Do not clean policy for dependent rules
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
        load_path = os.path.join(self.args.FOLDER, self.TAGS_DIR)
        if form == "yaml":
            for filename in os.listdir(load_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    self.LOADED_TAGS.append(load_from_yaml(os.path.join(load_path, filename)))
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

    def load_policies(self, form="yaml"):
        load_path = os.path.join(self.args.FOLDER, self.POLICIES_DIR)
        if form == "yaml":
            for filename in os.listdir(load_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    self.LOADED_POLICIES.append(load_from_yaml(os.path.join(load_path, filename)))
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

    def load_rules(self, form="yaml"):
        load_path = os.path.join(self.args.FOLDER, self.RULES_DIR)
        if form == "yaml":
            for filename in os.listdir(load_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    self.LOADED_RULES.append(load_from_yaml(os.path.join(load_path, filename)))
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

    def load_events(self, form="yaml"):
        load_path = os.path.join(self.args.FOLDER, self.EVENTS_DIR)
        if form == "yaml":
            for filename in os.listdir(load_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    self.LOADED_EVENTS.append(load_from_yaml(os.path.join(load_path, filename)))
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

    def load_alerts(self, form="yaml"):
        load_path = os.path.join(self.args.FOLDER, self.ALERTS_DIR)
        if form == "yaml":
            for filename in os.listdir(load_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    self.LOADED_ALERTS.append(load_from_yaml(os.path.join(load_path, filename)))
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

    def load_actions(self, form="yaml"):
        load_path = os.path.join(self.args.FOLDER, self.ACTIONS_DIR)
        if form == "yaml":
            for filename in os.listdir(load_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    self.LOADED_ACTIONS.append(load_from_yaml(os.path.join(load_path, filename)))
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

    def load_blacklist_ip(self, form="yaml"):
        load_path = os.path.join(self.args.FOLDER, self.BLACKLIST_IP_DIR)
        if form == "yaml":
            for filename in os.listdir(load_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    self.LOADED_BLACKLIST_IP.append(load_from_yaml(os.path.join(load_path, filename)))
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

    def load_blacklist_hosts(self, form="yaml"):
        load_path = os.path.join(self.args.FOLDER, self.BLACKLIST_HOSTS_DIR)
        if form == "yaml":
            for filename in os.listdir(load_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    self.LOADED_BLACKLIST_HOSTS.append(load_from_yaml(os.path.join(load_path, filename)))
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

    def load_firewall(self, form="yaml"):
        load_path = os.path.join(self.args.FOLDER, self.FIREWALL_DIR)
        if form == "yaml":
            for filename in os.listdir(load_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    self.LOADED_FIREWALL.append(load_from_yaml(os.path.join(load_path, filename)))
        else:
            raise NotImplementedError("Load as {} isn't implemented".format(form))

    def load(self, form="yaml"):
        self.load_tags(form)
        self.load_policies(form)
        self.load_rules(form)
        self.load_events(form)
        self.load_alerts(form)
        self.load_actions(form)
        self.load_blacklist_ip(form)
        self.load_blacklist_hosts(form)
        self.load_firewall(form)

    # Methods for DB update
    def commit(self):
        self.commit_actions()
        self.commit_alerts()
        self.commit_events()
        self.commit_policies()
        self.commit_rules()
        self.commit_tags()
        self.commit_blacklist_ip()
        self.commit_blacklist_hosts()
        self.commit_firewall()

    def commit_actions(self):
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

        for loaded in self.ACTIONS:
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(loaded)
            else:
                stored = {}
                for a in self.STORED_ACTIONS:
                    if a['_id'] == loaded["_id"]:
                        stored = a
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(loaded)
                else:
                    replace_one(loaded)

    def commit_alerts(self):
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

        for loaded in self.ALERTS:
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(loaded)
            else:
                stored = {}
                for a in self.STORED_ALERTS:
                    if a['_id'] == loaded["_id"]:
                        stored = a
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(loaded)
                else:
                    replace_one(loaded)

    def commit_events(self):
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

        for loaded in self.EVENTS:
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(loaded)
            else:
                stored = {}
                for e in self.STORED_EVENTS:
                    if e['_id'] == loaded["_id"]:
                        stored = e
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(loaded)
                else:
                    replace_one(loaded)

    def commit_policies(self):
        def build_update(o):
            tmp = o
            protectors = ["AuthLDAP", "AuthOracle", "BlacklistProtector", "CSPProtector",
                          "CSRFProtector", "DDoSProtector", "HMMProtector", "HTTPProtector",
                          "ICAPProtector", "JSONProtector", "OpenRedirectProtector", "ResponseFilter",
                          "RobotProtector", "RuleEngine", "RVPProtector", "ScriptEngine",
                          "SessionCookieProtector", "SQLiProtector", "XMLProtector",
                          "XSSProtector"]
            wafjs_modules = ["botdetector", "domauth", "domcleaner", "domdetective"]

            res = {"$set": {}}
            if not self.args.IMPORT_EXCLUDES:  # Remove filters
                # Clean policy filter
                if "filters" in tmp.keys():
                    del tmp['filters']
                # Clean protectors' filters
                for p in protectors:
                    if p in tmp.keys() and tmp[p]:
                        if 'filters' in tmp[p].keys():
                            del tmp[p]['filters']
                # Clean filters for WafJs modules
                for m in wafjs_modules:
                    if 'filters' in tmp["WafJsProtector"][m].keys():
                        del tmp["WafJsProtector"][m]['filters']

            res["$set"] = tmp

            return res

        def replace_one(o):
            self.mongo.replace_one('policies', str(o['_id']), o)

        def update_one(o):
            self.mongo.update_one('policies', str(o['_id']), build_update(o))

        def is_newer(stored, loaded):
            return True  # Always update policies

        for loaded in self.POLICIES:
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(loaded)
            else:
                stored = {}
                for t in self.STORED_POLICIES:
                    if t['_id'] == loaded["_id"]:
                        stored = t
                        break
                if stored:
                    if is_newer(stored, loaded):
                        update_one(loaded)
                else:
                    replace_one(loaded)

    def commit_rules(self):
        def build_update(loaded, stored):
            tmp = loaded
            res = {"$set": {}}

            if not self.args.IMPORT_EXCLUDES:  # Do not update excludes
                if "filters" in tmp.keys():
                    del tmp['filters']

            if "policies" in tmp.keys():  # Do not update policies
                del tmp['policies']

            if "custom_policies" in tmp.keys():  # Do not update custom policy actions
                del tmp['custom_policies']

            if "tags" in tmp.keys() and tmp['tags']:  # Join new tags with stored ones
                if "tags" in stored.keys():
                    tags = stored["tags"]
                else:
                    tags = list()
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

        for loaded in self.RULES:
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(loaded)
            else:
                stored = {}
                for t in self.STORED_RULES:
                    if t['_id'] == loaded["_id"]:
                        stored = t
                        break
                if stored:
                    if is_newer(stored, loaded):
                        update_one(loaded, stored)
                else:
                    replace_one(loaded)

    def commit_tags(self):
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

        for loaded in self.TAGS:
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(loaded)
            else:
                stored = {}
                for t in self.STORED_TAGS:
                    if t['_id'] == loaded["_id"]:
                        stored = t
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(loaded)
                else:
                    replace_one(loaded)

    def commit_blacklist_ip(self):
        def replace_one(o):
            self.mongo.replace_one('blacklist.ip', str(o['_id']), o)

        def is_newer(stored, loaded):
            return loaded['last_modified'] > stored['last_modified']

        for loaded in self.BLACKLIST_IP:
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(loaded)
            else:
                stored = {}
                for i in self.STORED_BLACKLIST_IP:
                    if i['_id'] == loaded["_id"]:
                        stored = i
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(loaded)
                else:
                    replace_one(loaded)

    def commit_blacklist_hosts(self):
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

        for loaded in self.BLACKLIST_HOSTS:
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(loaded)
            else:
                stored = {}
                for h in self.STORED_BLACKLIST_HOSTS:
                    if h['_id'] == loaded["_id"]:
                        stored = h
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(loaded)
                else:
                    replace_one(loaded)

    def commit_firewall(self):
        def replace_one(o):
            self.mongo.replace_one('ipset', str(o['_id']), o)

        def is_newer(stored, loaded):
            return loaded['last_modified'] > stored['last_modified']

        for loaded in self.FIREWALL:
            if self.args.FORCE_REPLACE:  # Forcing update all the objects
                replace_one(loaded)
            else:
                stored = {}
                for r in self.FIREWALL:
                    if r['_id'] == loaded["_id"]:
                        stored = r
                        break
                if stored:
                    if is_newer(stored, loaded):
                        replace_one(loaded)
                else:
                    replace_one(loaded)


if __name__ == "__main__":
    r = Run(parse_cli_args(), MongoDB())
    r.bootstrap()

    # Load from files
    r.load()

    # Get data
    r.go()

    # Commit data to storage
    r.commit()

    print("DONE!")