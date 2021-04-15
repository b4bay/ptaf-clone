import argparse
import subprocess
from pymongo import MongoClient
from bson import ObjectId
from bson.errors import InvalidId
from copy import deepcopy

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

    def fetch_all(self, collection_name, filt={}, excluded_fields=[]):
        res = []
        collections = self.db.collection_names()
        if collection_name in collections:
            storage = self.db[collection_name]
            excluded = {}
            for field in excluded_fields:
                excluded[field] = False
            if excluded:
                db_iterator = storage.find(filt, excluded)
            else:
                db_iterator = storage.find(filt)
            for doc in db_iterator:
                res.append(doc)
        return res

    def fetch_one(self, collection_name, filt={}, excluded_fields=[]):
        res = {}
        collections = self.db.collection_names()
        if collection_name in collections:
            storage = self.db[collection_name]
            excluded = {}
            for field in excluded_fields:
                excluded[field] = False
            if excluded:
                res = storage.find_one(filt, excluded)
            else:
                res = storage.find_one(filt)
        return res

    def replace_one(self, collection_name, filt, replacement):
        if type(filt) == str:  # Means filter by ObjectId
            try:
                filt = {"_id": ObjectId(filt)}
            except InvalidId:
                print("[!] Object ID {} is invalid, ignoring".format(filt))
                return

        storage = self.db[collection_name]
        storage.find_one_and_replace(filt, replacement, upsert=True)

    def update_one(self, collection_name, filt, update):
        if type(filt) == str:  # Means filter by ObjectId
            try:
                filt = {"_id": ObjectId(filt)}
            except InvalidId:
                print("[!] Object ID {} is invalid, ignoring".format(filt))
                return

        storage = self.db[collection_name]
        storage.find_one_and_update(filt, update)

    def delete_one(self, collection_name, filt):
        if type(filt) == str:  # Means filter by ObjectId
            try:
                filt = {"_id": ObjectId(filt)}
            except InvalidId:
                print("[!] Object ID {} is invalid, ignoring".format(filt))
                return

        storage = self.db[collection_name]
        storage.find_one_and_delete(filt)


def parse_cli_args(test_data=""):
    parser = argparse.ArgumentParser(description='Import data to PT AF')
    parser.add_argument('CLASS',
                        action='store',
                        choices=["all", "rules", "events", "alerts", "tags", "actions"],
                        help='Class of object(s) to remove. Use "all" to remove all the supported classes.')

    if test_data:
        args = parser.parse_args(test_data)
    else:
        args = parser.parse_args()

    return args


class Run:
    def __init__(self, args, mongo):
        if not mongo:
            mongo = MongoDB()
        self.mongo = mongo
        self.args = args
        self.STORED_POLICIES = list()
        self.STORED_ALERTS = list()
        self.STORED_RULES = list()
        self.STORED_EVENTS = list()
        self.STORED_TAGS = list()
        self.STORED_ACTIONS = list()

    def bootstrap(self):
        #all_except_default_policies = {"_id": {"$not": ObjectId("528e2758cd80bc1b8633f863")}}
        all_policies = {}
        all_rules = {}
        all_alerts = {}
        all_events = {}
        all_tags = {}
        all_actions = {}
        self.STORED_POLICIES = self.mongo.fetch_all('policies', filt=all_policies)
        self.STORED_ALERTS = self.mongo.fetch_all('alerts', filt=all_alerts)
        self.STORED_RULES = self.mongo.fetch_all('rules', filt=all_rules)
        self.STORED_EVENTS = self.mongo.fetch_all('events', filt=all_events)
        self.STORED_TAGS = self.mongo.fetch_all('tags', filt=all_tags)
        self.STORED_ACTIONS = self.mongo.fetch_all('actions', filt=all_actions)

    def go_single(self):
        if self.args.CLASS == "policies":
            self.empty_policies()
        elif self.args.CLASS == "alerts":
            self.empty_alerts()
        elif self.args.CLASS == "rules":
            self.empty_rules()
        elif self.args.CLASS == "events":
            self.empty_events()
        elif self.args.CLASS == "tags":
            self.empty_tags()
        elif self.args.CLASS == "actions":
            self.empty_actions()
        else:
            raise KeyError("Unknown class to delete: {}".format(self.args.CLASS))

    def go_all(self):
        # Clean all the policies
        self.args.CLASS = 'policies'
        self.go_single()

        # Clean all the events
        self.args.CLASS = 'events'
        self.go_single()

        # Clean all the alerts
        self.args.CLASS = 'alerts'
        self.go_single()

        # Clean all the rules
        self.args.CLASS = 'rules'
        self.go_single()

        # Clean all the actions
        self.args.CLASS = 'actions'
        self.go_single()

        # Clean all the tags
        self.args.CLASS = 'tags'
        self.go_single()

    def go(self):
        if self.args.CLASS == "all":
            self.go_all()
        else:
            self.go_single()

    def empty_policies(self):
        def clean(obj):
            res = deepcopy(obj)
            return res

        def delete_one(o):
            self.mongo.delete_one('policies', str(o['_id']))

        for policy in self.STORED_POLICIES:
            clean_policy = clean(policy)
            delete_one(clean_policy)

    def empty_alerts(self):
        def clean(obj):
            res = deepcopy(obj)
            return res

        def delete_one(o):
            self.mongo.delete_one('alerts', str(o['_id']))

        for alert in self.STORED_ALERTS:
            clean_alert = clean(alert)
            delete_one(clean_alert)

    def empty_events(self):
        def clean(obj):
            res = deepcopy(obj)
            return res

        def delete_one(o):
            self.mongo.delete_one('events', str(o['_id']))

        for event in self.STORED_EVENTS:
            clean_event = clean(event)
            delete_one(clean_event)

    def empty_rules(self):
        def clean(obj):
            res = deepcopy(obj)
            return res

        def delete_one(o):
            self.mongo.delete_one('rules', str(o['_id']))

        for rule in self.STORED_RULES:
            clean_rule = clean(rule)
            delete_one(clean_rule)

    def empty_actions(self):
        def clean(obj):
            res = deepcopy(obj)
            return res

        def delete_one(o):
            self.mongo.delete_one('actions', str(o['_id']))

        for action in self.STORED_ACTIONS:
            clean_action = clean(action)
            delete_one(clean_action)

    def empty_tags(self):
        def clean(obj):
            res = deepcopy(obj)
            return res

        def delete_one(o):
            self.mongo.delete_one('tags', str(o['_id']))

        for tag in self.STORED_TAGS:
            clean_tag = clean(tag)
            delete_one(clean_tag)

if __name__ == "__main__":
    r = Run(parse_cli_args(), MongoDB())
    r.bootstrap()

    # Get data
    r.go()

    print("DONE!")