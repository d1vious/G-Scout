import json
import logging
import os
from jinja2 import Environment, PackageLoader
from tinydb import Query
from core.utility import object_id_to_directory_name

try:
    to_unicode = unicode
except NameError:
    to_unicode = str


logging.basicConfig(filename="log.txt")
env = Environment(loader=PackageLoader('assets', 'templates'), extensions=['jinja2.ext.do'])


def pretty_print(dict):
    try:
        return json.dumps(dict, sort_keys=True, indent=4, separators=(',', ': '))
    except:
        return dict


env.filters['pretty_print'] = pretty_print

class Dump(object):
    def __init__(self,obj):
        for attr in dir(obj):
            print "obj.%s = %s" % (attr, getattr(obj, attr))

def display_results(db, projectId):
    def add_to_dropdown(category):
        rules = set([])
        for rule in db.table("Rule").search(Query().category == category):
            if db.table('Finding').search(Query().rule.id == rule.eid):
                rules.add(rule['title'])
        return rules

    def generate_entities_page(category, header, fields, dropdowns):
        reports = []
        try:
            records = db.table(category).all()
            template = env.get_template("entity_template.html")
            entity_file_path = "Report Output/" + object_id_to_directory_name(projectId) + "/Information/" + category + "s.html"
            entity_dir_path = os.path.dirname(entity_file_path)
            if not os.path.isdir(entity_dir_path):
                os.makedirs(entity_dir_path)

            for r in records:
                value = dict()
                i = dict()

                # cast record from tinydb document to dict
                for k, v in r.iteritems():
                    value[k] = v
                i['project'] = projectId
                i['check'] = "configs"
                i['value'] = value
                i['category'] = category
                i['type'] = 'PASS'
                reports.append(i)

            file = open(entity_file_path, "w+")
            file_content = None
            try:
                file_content = template.render(**{"records": records, "dropdowns": dropdowns, "header": header, "fields": fields})
            except Exception as e:
                print("Error rendering output file '%s': %s" % (entity_file_path, e))
            if file_content:
                file.write(file_content)
            file.close()
        except Exception as e:
            print("Error generating output file '%s': %s" % (entity_file_path, e))

        return reports

    def generate_findings_page(category, header, fields, dropdowns):
        reports = []
        try:
            for rule_title in dropdowns[category]:
                rule = db.table("Rule").get(Query().title == rule_title)
                findings = db.table("Finding").search(Query().rule.id == rule.eid)
                findings = [db.table(finding['entity']['table']).get(eid=finding['entity']['id']) for finding in
                            findings]
                template = env.get_template("finding_template.html")
                finding_file_path = "Report Output/" + object_id_to_directory_name(projectId) + "/Findings/" + rule_title + ".html"
                finding_dir_path = os.path.dirname(finding_file_path)
                if not os.path.isdir(finding_dir_path):
                    os.makedirs(finding_dir_path)

                i = dict()
                i['project'] = projectId
                i['check'] = rule_title
                i['value'] = findings
                i['category'] = category
                i['type'] = 'WARNING'
                reports.append(i)

                file = open(finding_file_path, "w+")
                file_content = None
                try:
                    file_content = template.render(
                        **{"records": findings, "dropdowns": dropdowns, "header": header, "fields": fields,
                           "text": rule['title']})
                except Exception as e:
                    print("Error rendering output file '%s': %s" % (finding_file_path, e))
                if file_content:
                    file.write(file_content)
                file.close()

        except KeyError as ke:
            pass
        except Exception as e:
            print("Error generating output file '%s': %s" % (finding_file_path, e))

        return reports

    # The following would place only categories with findings in the navbar
    # for finding in findings_table.all():
    #         categories.add(finding['entity']['table'])
    # for category in categories:
    #         dropdowns[category] = add_to_dropdown(category)

    # The header is the name of the field that will be bolded
    def generate_pages(category, header, fields, dropdowns):

        try:
            findings_report = generate_findings_page(category, header, fields, dropdowns)
        except Exception as e:
            logging.exception("findings page")
        try:
            entities_report = generate_entities_page(category, header, fields, dropdowns)
        except Exception as e:
            logging.exception("entities page")

        reports = []
        for i in findings_report:
            reports.append(i)
        for i in entities_report:
            reports.append(i)
        return reports

    def process_log(report):
        if len(report) > 0:
            current_report = []
            for i in report:
                report_path = "Report Output/" + i['project'] + "/reports.json"
                if os.path.exists(report_path):
                    with open(report_path, 'r') as log:
                        current_report = json.load(log)
                        current_report.append(i)
                    with open(report_path, 'w') as log:
                        json.dump(current_report, log)
                else:
                    current_report.append(i)
                    with open(report_path, 'w') as log:
                        json.dump(current_report, log)

    # Navbar dropdowns
    dropdowns = {}
    categories = set([])

    for rule in db.table("Rule").all():
        categories.add(rule['category'])
    for category in categories:
        dropdowns[category] = add_to_dropdown(category)
    process_log(generate_pages("Bucket", "name", ["selfLink", "location", "storageClass", "acls", "defacls"], dropdowns))

    process_log(generate_pages("Firewall", "name",
                   ["network", "sourceRanges", "sourceTags","direction", "destinationRanges", "allowed", "description", "targetTags",
                    "affectedInstances"], dropdowns))
    process_log(generate_pages("Network", "selfLink", ["name", "description", "firewallRules", "members", "subnetworks"], dropdowns))
    process_log(generate_pages("Subnet", "selfLink", ["name", "region", "network", "ipCidrRange", "gatewayAddress", "enableFlowLogs", "privateIpGoogleAccess"], dropdowns))
    process_log(generate_pages("Role", "role", ["members"], dropdowns))
    process_log(generate_pages("Compute Engine", "name", ["selfLink", "machineType", "status", "startRestricted", "serviceAccounts", "networkInterfaces", "disks", "tags"], dropdowns))
    process_log(generate_pages("SQL Instance", "name",
                   ["selfLink", "connectionName", "databaseVersion", "ipAddress", ["settings", "dataDiskSizeGb"], ["settings", "backupConfiguration"],
                    ["settings", "ipConfiguration"], "serviceAccountEmailAddress", "gceZone" ], dropdowns))
    process_log(generate_pages("Service Account", "displayName", ["email", "name", "keys", "iam_policies", "uniqueId", "roles"], dropdowns))
    process_log(generate_pages("Address", "address", ["addressType","name","purpose","subnetwork"], dropdowns))
    process_log(generate_pages("Cluster", "name", ["nodeConfig", "addonsConfig","loggingService","privateClusterConfig","enablePrivateNodes","podSecurityPolicyConfig"], dropdowns))

