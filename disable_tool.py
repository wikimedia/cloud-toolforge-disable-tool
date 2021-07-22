#!/usr/bin/python3
"""
Copyright 2021 Andrew Bogott
Copyright 2021 Wikimedia Foundation, Inc.

This script is free software, and comes with ABSOLUTELY NO WARRANTY.
It may be used, redistributed and/or modified under the terms of the GNU
General Public Licence (see http://www.fsf.org/licensing/licenses/gpl.txt).


This script implements several commands. Each command does part of the work to
disable and/or delete a toolforge tool. It's designed to run asyncronously
on several different servers; in some case the order of operations doesn't matter
but when order does matter flag files (*.disabled) are written to the tool
homedir to signal which phases are complete.
"""

import argparse
from copy import deepcopy
import datetime
import configparser
import glob
import ldap
from ldap import modlist
import logging
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile

logging.basicConfig(filename="/var/log/disable-tool.log", level=logging.INFO)
LOG = logging.getLogger(__name__)


def _getLdapInfo(attr, conffile="/etc/ldap.conf"):
    try:
        f = open(conffile)
    except IOError:
        if conffile == "/etc/ldap.conf":
            # fallback to /etc/ldap/ldap.conf, which will likely
            # have less information
            f = open("/etc/ldap/ldap.conf")
    for line in f:
        if line.strip() == "":
            continue
        if line.split()[0].lower() == attr.lower():
            return line.split(None, 1)[1].strip()
            break


def _open_ldap(binddn=None, bindpw=None):
    ldapHost = _getLdapInfo("uri")
    sslType = _getLdapInfo("ssl")

    if binddn is None:
        binddn = _getLdapInfo("BINDDN")

    if bindpw is None:
        bindpw = _getLdapInfo("BINDPW")

    ds = ldap.initialize(ldapHost)
    ds.protocol_version = ldap.VERSION3
    if sslType == "start_tls":
        ds.start_tls_s()

    try:
        ds.simple_bind_s(binddn, bindpw)
        return ds
    except ldap.CONSTRAINT_VIOLATION:
        LOG.debug("LDAP bind failure:  Too many failed attempts.\n")
    except ldap.INVALID_DN_SYNTAX:
        LOG.debug("LDAP bind failure:  The bind DN is incorrect... \n")
    except ldap.NO_SUCH_OBJECT:
        LOG.debug("LDAP bind failure:  " "Unable to locate the bind DN account.\n")
    except ldap.UNWILLING_TO_PERFORM as msg:
        LOG.debug(
            "LDAP bind failure:  "
            "The LDAP server was unwilling to perform the action"
            " requested.\nError was: %s\n" % msg[0]["info"]
        )
    except ldap.INVALID_CREDENTIALS:
        LOG.debug("LDAP bind failure:  Password incorrect.\n")

    return None


def _disabled_datestamps(ds):
    disableddict = {}

    basedn = "ou=people,ou=servicegroups,dc=wikimedia,dc=org"
    disabled_tools = ds.search_s(
        basedn, ldap.SCOPE_ONELEVEL, "(pwdAccountLockedTime=*)", ["*", "+"]
    )

    for tool in disabled_tools:
        toolname = tool[1]["cn"][0].decode("utf8").split(".")[1]
        timestamp = tool[1]["pwdAccountLockedTime"][0].decode("utf8")
        uid = tool[1]["uidNumber"][0].decode("utf8")
        if timestamp == "000001010000Z":
            # This is a special case which we'll interpret to mean
            #  'disable and archive immediately'
            disableddict[toolname] = uid, None
        else:
            disableddict[toolname] = (
                uid,
                datetime.datetime.strptime(timestamp.rstrip("Z"), "%Y%m%d%H%M%S"),
            )

    return disableddict


def _is_expired(datestamp, days):
    return datestamp is None or ((datetime.datetime.now() - datestamp).days > days)


CRON_DIR = "/var/spool/cron/crontabs"
TOOL_HOME_DIR = "/data/project/"
DISABLED_CRON_NAME = "crontab.disabled"


# When this finishes, each disabled tool will have a crontab.disabled
# file in its $home and no active cron.
#
# No active tool will have a crontab.disabled file.
def reconcile_crontabs(disabled_tools):
    # First, decide what we need to do with some set arithmetic.
    should_be_disabled = set(disabled_tools)

    # Find all already-disabled crontabs
    disabled_cron_files = glob.glob(
        TOOL_HOME_DIR + "/*/%s" % DISABLED_CRON_NAME, recursive=True
    )
    already_disabled = set(
        [os.path.basename(os.path.dirname(p)) for p in disabled_cron_files]
    )

    to_disable = should_be_disabled - already_disabled
    to_enable = already_disabled - should_be_disabled

    for tool in to_disable:
        cronfile = os.path.join(CRON_DIR, "tools.%s" % tool)
        archivefile = os.path.join(TOOL_HOME_DIR, tool, DISABLED_CRON_NAME)

        LOG.info("Archiving crontab for %s" % tool)
        if os.path.isfile(cronfile):
            # we can't use os.rename across different volumes.
            subprocess.check_output(["mv", cronfile, archivefile])
        else:
            # Create an empty archive as a placeholder
            pathlib.Path(archivefile).touch()

    for tool in to_enable:
        cronfile = os.path.join(CRON_DIR, "tools.%s" % tool)
        archivefile = os.path.join(TOOL_HOME_DIR, tool, DISABLED_CRON_NAME)

        LOG.info("Restoring crontab for %s" % tool)

        if os.path.isfile(cronfile):
            LOG.warning(
                "Tool %s has both an active crontab and and archived crontab" % tool
            )
        else:
            if os.path.getsize(archivefile):
                subprocess.check_output(["mv", archivefile, cronfile])
            else:
                os.remove(archivefile)


QUOTA_SUFFIX = "_disable"


def _list_grid_quotas():
    quotas = subprocess.check_output(["/usr/bin/qconf", "-srqsl"])
    quota_list = [
        quota[: quota.rfind(QUOTA_SUFFIX)]
        for quota in quotas.decode("utf8").splitlines()
    ]
    return quota_list


def _create_grid_quota(tool):
    quota_file_content = "{\n"
    quota_file_content += "name         %s%s\n" % (tool, QUOTA_SUFFIX)
    quota_file_content += "description  disable %s\n" % tool
    quota_file_content += "enabled      TRUE\n"
    quota_file_content += "limit        users tools.%s to slots=0\n" % tool
    quota_file_content += "}\n"
    with tempfile.NamedTemporaryFile(dir="/tmp", delete=True) as tmpfile:
        tmpfile.write(quota_file_content.encode("utf8"))
        tmpfile.flush()
        subprocess.check_output(["/usr/bin/qconf", "-Arqs", tmpfile.name])


def _has_grid_quota(tool):
    quotas = subprocess.check_output(["/usr/bin/qconf", "-srqsl"])
    return "%s%s" % (tool, QUOTA_SUFFIX) in quotas.decode("utf8").splitlines()


def _delete_grid_quota(tool):
    if _has_grid_quota(tool):
        subprocess.check_output(
            ["/usr/bin/qconf", "-drqs", "%s%s" % (tool, QUOTA_SUFFIX)]
        )


DISABLED_GRID_FILE = "grid.disabled"
DISABLED_K8S_FILE = "k8s.disabled"


# Make sure everything is properly stopped before we start deleting stuff
def _is_ready_for_archive_and_delete(tool_home):
    cron_archive = os.path.join(tool_home, DISABLED_CRON_NAME)
    if not os.path.isfile(cron_archive):
        return False

    disabled_grid_file = os.path.join(tool_home, DISABLED_GRID_FILE)
    if not os.path.isfile(disabled_grid_file):
        return False

    disabled_k8s_file = os.path.join(tool_home, DISABLED_K8S_FILE)
    if not os.path.isfile(disabled_k8s_file):
        return False

    return True


# Ensure that disabled tools prevent any new grid jobs from starting
#  with a restrictive quota.
# Also ensure that the restrictive quota has been removed for any
#  tools that have been re-enabled.
def reconcile_grid_quotas(disabled_tools):
    should_be_disabled = set(disabled_tools)
    already_disabled = set(_list_grid_quotas())

    to_disable = should_be_disabled - already_disabled
    to_enable = already_disabled - should_be_disabled

    for tool in to_disable:
        cron_archive = os.path.join(TOOL_HOME_DIR, tool, DISABLED_CRON_NAME)
        if not os.path.isfile(cron_archive):
            LOG.warning(
                "Tool %s may still have an active cron; postponing grid disable" % tool
            )
            continue

        LOG.info("Disabling grid jobs for %s" % tool)
        _create_grid_quota(tool)

        disabled_flag_file = os.path.join(TOOL_HOME_DIR, tool, DISABLED_GRID_FILE)
        pathlib.Path(disabled_flag_file).touch()

    for tool in to_enable:
        LOG.info("Enabling grid jobs for %s" % tool)
        _delete_grid_quota(tool)

        disabled_flag_file = os.path.join(TOOL_HOME_DIR, tool, DISABLED_GRID_FILE)
        if os.path.exists(disabled_flag_file):
            os.remove(disabled_flag_file)


def _get_grid_jobs(tool):
    qstat_output = subprocess.check_output(
        ["/usr/bin/qstat", "-ne", "-u", "tools.%s" % tool]
    )
    # The first two lines are headers. The first entry in subsequent lines is the job id
    jobs = [line.split()[0] for line in qstat_output.splitlines()[2:]]
    return jobs


# Kill all SGE jobs owned by the specified tool
def _kill_grid_jobs(tool):
    for job in _get_grid_jobs(tool):
        subprocess.check_output(["/usr/bin/qdel", job])


# Delete all ldap references to the specified tool.
def _delete_ldap_entries(tool, conf):
    if not _is_ready_for_archive_and_delete(os.path.join(TOOL_NFS_BASE_DIR, tool)):
        LOG.info(
            "Tool %s is expired but not properly shut down yet, skipping file archive"
        )
        return

    # Get a special ldap session with read/write permissions
    novaadmin_ds = _open_ldap(
        conf["archive"]["ldap_bind_dn"], conf["archive"]["ldap_bind_pass"]
    )

    # Doublecheck that our creds are working and we sould really
    #  delete this
    disabled_tools = _disabled_datestamps(novaadmin_ds)
    if tool not in disabled_tools:
        LOG.warning("Asked to delete %s but can't confirm that it's disabled." % tool)
        return

    tool_dn = "cn=tools.%s,ou=servicegroups,dc=wikimedia,dc=org" % tool
    tool_user_dn = "uid=tools.%s,ou=people,ou=servicegroups,dc=wikimedia,dc=org" % tool

    # First, remove references to this tool_user_dn in other tools
    tool_base_dn = "ou=servicegroups,dc=wikimedia,dc=org"
    all_tools = novaadmin_ds.search_s(
        tool_base_dn, ldap.SCOPE_ONELEVEL, "(objectClass=groupOfNames)", ["*"]
    )
    for thistool in all_tools:
        if tool_user_dn.encode("utf8") in thistool[1]["member"]:
            toremove = tool_user_dn.encode("utf8")
            new = deepcopy(thistool[1])
            new["member"].remove(toremove)
            ldif = modlist.modifyModlist(thistool[1], new)
            novaadmin_ds.modify_s(thistool[0], ldif)

    # Now remove the tool itself
    novaadmin_ds.delete_s(tool_user_dn)
    novaadmin_ds.delete_s(tool_dn)
    novaadmin_ds.unbind()


TOOL_NFS_BASE_DIR = "/srv/tools/shared/tools/project/"
TOOL_NFS_ARCHIVE_DIR = "/srv/tools/archivedtools/"


# Make a tarball of the tool's project dir on TOOL_NFS_ARCHIVE_DIR,
#  then delete the project dir.
def _archive_home(tool):
    tool_dir = os.path.join(TOOL_NFS_BASE_DIR, tool)

    if not _is_ready_for_archive_and_delete(os.path.join(TOOL_NFS_BASE_DIR, tool)):
        LOG.info(
            "Tool %s is expired but not properly shut down yet, skipping file archive"
        )
        return

    archivepath = os.path.join(TOOL_NFS_ARCHIVE_DIR, tool)
    args = ["tar", "-cpzf", archivepath, tool_dir]
    rval = subprocess.call(args)
    if rval:
        logging.info(
            "Failed to archive %s with exit code %s. "
            "Command was: %s" % (tool, rval, " ".join(args))
        )
        return False
    else:
        logging.info("Archived %s to %s" % (tool_dir, archivepath))

    logging.info("Archive complete; removing %s" % tool_dir)
    shutil.rmtree(tool_dir)


def crontab(conf):
    if "sgecron" not in socket.gethostname():
        LOG.error("This command can only be run on an sgecron node")
        exit(3)

    ds = _open_ldap()
    reconcile_crontabs(_disabled_datestamps(ds))


def gridengine(conf):
    if conf["gridengine"]["hostname_substring"] not in socket.gethostname():
        LOG.error("This command can only be run on a gridengine master node")
        exit(2)

    ds = _open_ldap()
    disabled_tools = _disabled_datestamps(ds)
    for tool in disabled_tools:
        _kill_grid_jobs(tool)
    reconcile_grid_quotas(disabled_tools)


def archive(conf):
    if conf["archive"]["hostname_substring"] not in socket.gethostname():
        LOG.error("This command can only be run on the toolforge nfs server")
        exit(4)

    ds = _open_ldap()
    disabled_tools = _disabled_datestamps(ds)
    for tool in disabled_tools:
        _uid, datestamp = disabled_tools[tool]
        if _is_expired(datestamp, int(conf["default"]["archive_after_days"])):
            if not _is_ready_for_archive_and_delete(
                os.path.join(TOOL_NFS_BASE_DIR, tool)
            ):
                LOG.info("Tool %s is expired but not properly shut down yet")
                continue

            _archive_home(tool)
            _delete_ldap_entries(tool, conf)


REPLICA_CONF = "replica.my.cnf"


def archive_dbs(conf):
    import mysql.connector

    if conf["db"]["hostname_substring"] not in socket.gethostname():
        LOG.error("This command can only be run on the toolforge database server")
        exit(5)

    ds = _open_ldap()
    disabled_tools = _disabled_datestamps(ds)
    for tool in disabled_tools:
        uid, datestamp = disabled_tools[tool]
        if _is_expired(datestamp, int(conf["default"]["archive_after_days"])):
            if not _is_ready_for_archive_and_delete(os.path.join(TOOL_HOME_DIR, tool)):
                LOG.info("Tool %s is expired but not properly shut down yet" % tool)
                continue

            db_conf = os.path.join(TOOL_HOME_DIR, tool, REPLICA_CONF)
            if not os.path.isfile(db_conf):
                # No replica.my.cnf so nothing to do
                continue
            dbconfig = configparser.ConfigParser()
            dbconfig.read(db_conf)
            connection = mysql.connector.connect(
                host="tools.db.svc.wikimedia.cloud",
                user=dbconfig["client"]["user"],
                password=dbconfig["client"]["password"],
            )
            mycursor = connection.cursor()
            mycursor.execute(
                "SHOW databases LIKE '%s__%%';" % dbconfig["client"]["user"]
            )
            dbs = mycursor.fetchall()
            for db in dbs:
                fname = os.path.join(TOOL_HOME_DIR, tool, "%s.mysql" % db[0])
                LOG.info("Dumping %s to %s" % (db[0], fname))
                f = open(fname, "w")
                args = [
                    "mysqldump",
                    "-u",
                    dbconfig["client"]["user"],
                    "--password=%s" % dbconfig["client"]["password"],
                    db[0],
                ]
                rval = subprocess.call(args, stdout=f)
                if rval == 0:
                    LOG.info("Dump succeeded; now dropping %s" % db[0])
                    mycursor.execute("DROP database %s;" % db[0])


CONFIG_FILE = "/etc/disable_tool.conf"
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "disable-tools",
        description="Disable tools that have "
        "pwdAccountLockedTime set in ldap."
        "This needs to be run on multiple hosts, "
        "in the appropriate mode on each host.",
    )

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    sp = parser.add_subparsers()
    sp_crontab = sp.add_parser(
        "crontab",
        help="Archive crontab entries for disabled tools to ~/crontab.disabled "
        "and replace crontab for active tools with archived crontabs.",
    )
    sp_crontab.set_defaults(func=crontab)

    sp_gridengine = sp.add_parser(
        "gridengine",
        help="Stop all grid jobs for disabled tools; set or remove restricted "
        "tool-specific quotas as appropriate.",
    )
    sp_gridengine.set_defaults(func=gridengine)

    sp_archive = sp.add_parser(
        "archive",
        help="Archive the home dir for all tools disabled for more than %s days"
        % config["default"]["archive_after_days"],
    )
    sp_archive.set_defaults(func=archive)

    sp_archivedbs = sp.add_parser(
        "archivedbs",
        help="Archive all databases used by a tool that's "
        "been disabled for more than %s days" % config["default"]["archive_after_days"],
    )
    sp_archivedbs.set_defaults(func=archive_dbs)

    args = parser.parse_args()

    if "func" in args:
        args.func(config)
    else:
        parser.print_help()
