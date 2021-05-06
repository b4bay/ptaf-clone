import argparse
import re
import subprocess
from pymongo import MongoClient
from bson import objectid, int64, ObjectId
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


def parse_cli_args(test_data=""):
    parser = argparse.ArgumentParser(description='Import data to PT AF')
    parser.add_argument('CLASS',
                        action='store',
                        choices=["all", "rules", "alerts"],
                        help='Class of object(s) to clean. Use "all" to clean all the supported classes.')

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
        self.STORED_ALERTS = list()
        self.STORED_RULES = list()

    def bootstrap(self):
        filt = {"_is_system": True}
        self.STORED_ALERTS = self.mongo.fetch_all('alerts', filt=filt)
        self.STORED_RULES = self.mongo.fetch_all('rules', filt=filt)

    def go_single(self):
        if self.args.CLASS == "alerts":
            self.clean_alerts()
        elif self.args.CLASS == "rules":
            self.clean_rules()
        else:
            raise KeyError("Unknown class to clean: {}".format(self.args.CLASS))

    def go_all(self):
        # Clean all the alerts
        self.args.CLASS = 'alerts'
        self.go_single()

        # Clean all the alerts
        self.args.CLASS = 'rules'
        self.go_single()

    def go(self):
        if self.args.CLASS == "all":
            self.go_all()
        else:
            self.go_single()

    def clean_alerts(self):
        def clean(obj):
            res = deepcopy(obj)
            res['enabled'] = False
            return res

        def replace_one(o):
            self.mongo.replace_one('alerts', str(o['_id']), o)

        for alert in self.STORED_ALERTS:
            clean_alert = clean(alert)
            replace_one(clean_alert)

    def clean_rules(self):
        def clean(obj):
            res = deepcopy(obj)
            res['enabled'] = False
            return res

        def replace_one(o):
            self.mongo.replace_one('rules', str(o['_id']), o)

        for rule in self.STORED_RULES:
            clean_rule = clean(rule)
            replace_one(clean_rule)


if __name__ == "__main__":
    r = Run(parse_cli_args(), MongoDB())
    r.bootstrap()

    # Get data
    r.go()

    print("DONE!")