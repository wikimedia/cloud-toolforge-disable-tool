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
import configparser
import datetime
import glob
import logging
import os
import pathlib
import pymysql
import shutil
import socket
import subprocess
import tempfile

import ldap
from ldap import modlist


logging.basicConfig(
    filename="/var/log/disable-tool.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
LOG = logging.getLogger(__name__)

QUOTA_SUFFIX = "_disable"
CRON_DIR = "/var/spool/cron/crontabs"
TOOL_HOME_DIR = "/data/project/"
DISABLED_CRON_NAME = "crontab.disabled"
SERVICE_MANIFEST_FILE = "service.manifest"
REPLICA_CONF = "replica.my.cnf"
CONFIG_FILE = "/etc/disable_tool.conf"


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


def _open_ldap(ldapHost=None, binddn=None, bindpw=None):
    sslType = _getLdapInfo("ssl")

    if ldapHost is None:
        ldapHost = _getLdapInfo("uri")

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
        LOG.debug("LDAP bind failure: Too many failed attempts.")
    except ldap.INVALID_DN_SYNTAX:
        LOG.debug("LDAP bind failure: The bind DN is incorrect...")
    except ldap.NO_SUCH_OBJECT:
        LOG.debug("LDAP bind failure: Unable to locate the bind DN account.")
    except ldap.UNWILLING_TO_PERFORM:
        LOG.exception(
            "LDAP bind failure: "
            "server was unwilling to perform the action requested."
        )
    except ldap.INVALID_CREDENTIALS:
        LOG.exception("LDAP bind failure: Password incorrect.")

    return None


def _disabled_datestamps(ds, projectname):
    disableddict = {}

    basedn = "ou=people,ou=servicegroups,dc=wikimedia,dc=org"
    policy = "cn=disabled,ou=ppolicies,dc=wikimedia,dc=org"
    disabled_tools = ds.search_s(
        basedn,
        ldap.SCOPE_ONELEVEL,
        "(&(|(pwdAccountLockedTime=*)(pwdPolicySubentry={}))(cn={}.*))".format(
            policy, projectname
        ),
        ["*", "+"],
    )

    for tool in disabled_tools:
        toolname = tool[1]["cn"][0].decode("utf8").split(".")[1]
        uid = tool[1]["uidNumber"][0].decode("utf8")
        if "pwdAccountLockedTime" in tool[1]:
            timestamp = tool[1]["pwdAccountLockedTime"][0].decode("utf8")
            if timestamp == "000001010000Z":
                # This is a special case which we'll interpret to mean
                #  'disable and archive immediately'
                expirestamp = datetime.datetime.min
            else:
                cleanstamp = timestamp.rstrip("Z")
                if "." not in cleanstamp:
                    cleanstamp = cleanstamp + ".0"
                expirestamp = datetime.datetime.strptime(
                    cleanstamp, "%Y%m%d%H%M%S.%f"
                )
        else:
            # This tool is marked as disabled but we don't have an expiration
            # date so we set the date to the far future; it will be treated as
            # disabled but never expire.
            expirestamp = datetime.datetime.max

        disableddict[toolname] = uid, expirestamp

    return disableddict


def _is_expired(datestamp, days):
    elapsed = (datetime.datetime.now() - datestamp).days
    LOG.info("Elapsed days is %s", elapsed)
    return elapsed > days


# When this finishes, each disabled tool will have a crontab.disabled
# file in its $home and no active cron.
#
# No active tool will have a crontab.disabled file.
def reconcile_crontabs(conf, disabled_tools):
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

        LOG.info("Archiving crontab for %s", tool)
        if os.path.isfile(cronfile):
            # we can't use os.rename across different volumes.
            subprocess.check_output(["mv", cronfile, archivefile])
        else:
            # Create an empty archive as a placeholder
            pathlib.Path(archivefile).touch()
        set_step_complete(conf, tool, "crontab_disabled")

    for tool in to_enable:
        cronfile = os.path.join(CRON_DIR, "tools.%s" % tool)
        archivefile = os.path.join(TOOL_HOME_DIR, tool, DISABLED_CRON_NAME)

        LOG.info("Restoring crontab for %s", tool)

        if os.path.isfile(cronfile):
            LOG.warning(
                "Tool %s has both an active crontab and and archived crontab",
                tool,
            )
        else:
            if os.path.getsize(archivefile):
                subprocess.check_output(["mv", archivefile, cronfile])
            else:
                os.remove(archivefile)
            set_step_complete(conf, tool, "crontab_disabled", state=False)


def _list_grid_quotas():
    try:
        quotas = subprocess.check_output(["/usr/bin/qconf", "-srqsl"])
        quota_list = [
            quota[: quota.rfind(QUOTA_SUFFIX)]
            for quota in quotas.decode("utf8").splitlines()
        ]
        return quota_list
    except subprocess.CalledProcessError:
        # qconf returns non-zero when there are no quotas -- that's fine.
        return []


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
    try:
        quotas = subprocess.check_output(["/usr/bin/qconf", "-srqsl"])
        return (
            "%s%s" % (tool, QUOTA_SUFFIX) in quotas.decode("utf8").splitlines()
        )
    except subprocess.CalledProcessError:
        # qconf returns non-zero when there are no quotas -- that's fine.
        return False


def _delete_grid_quota(tool):
    if _has_grid_quota(tool):
        subprocess.check_output(
            ["/usr/bin/qconf", "-drqs", "%s%s" % (tool, QUOTA_SUFFIX)]
        )


# Make sure everything is properly stopped before we start deleting stuff
def _is_ready_for_archive_and_delete(conf, tool, project):
    tool_home = _tool_dir(conf, tool, project)

    if not os.path.exists(tool_home):
        # This was archived on a prior path
        return True

    cron_archive = os.path.join(tool_home, DISABLED_CRON_NAME)
    if not os.path.isfile(cron_archive):
        return False

    if not get_step_complete(conf, tool, "grid_disabled"):
        return False

    if not get_step_complete(conf, tool, "kubernetes_disabled"):
        return False

    if not get_step_complete(conf, tool, "db_disabled"):
        return False

    return True


def reconcile_grid_quotas(conf, disabled_tools):
    """Ensure that disabled tools prevent any new grid jobs from starting with
    a restrictive quota. Also ensure that the restrictive quota has been
    removed for any tools that have been re-enabled.
    """
    should_be_disabled = set(disabled_tools)
    already_disabled = set(_list_grid_quotas())

    to_disable = should_be_disabled - already_disabled
    to_enable = already_disabled - should_be_disabled

    for tool in to_disable:
        cron_archive = os.path.join(TOOL_HOME_DIR, tool, DISABLED_CRON_NAME)
        if not os.path.isfile(cron_archive):
            LOG.warning(
                "Tool %s may still have an active cron; postponing grid disable",
                tool,
            )
            continue

        LOG.info("Disabling grid jobs for %s", tool)
        _create_grid_quota(tool)

        set_step_complete(conf, tool, "grid_disabled")

    for tool in to_enable:
        LOG.info("Enabling grid jobs for %s", tool)
        _delete_grid_quota(tool)

        set_step_complete(conf, tool, "grid_disabled", state=False)


def _get_grid_jobs(tool):
    qstat_output = subprocess.check_output(
        ["/usr/bin/qstat", "-ne", "-u", "tools.%s" % tool]
    )
    # The first two lines are headers. The first entry in subsequent lines is
    # the job id
    jobs = [line.split()[0] for line in qstat_output.splitlines()[2:]]
    return jobs


def _kill_grid_jobs(tool):
    """Kill all SGE jobs owned by the specified tool."""
    for job in _get_grid_jobs(tool):
        subprocess.check_output(["/usr/bin/qdel", job])


def _remove_service_manifest(tool):
    """Remove service.manifest so that webservicemonitor leaves this tool
    alone.
    """
    file_name = os.path.join(TOOL_HOME_DIR, tool, SERVICE_MANIFEST_FILE)
    if os.path.exists(file_name):
        os.remove(file_name)


def _delete_ldap_entries(conf, tool, project):
    """Delete all ldap references to the specified tool."""
    if not _is_ready_for_archive_and_delete(conf, tool, project):
        LOG.info(
            "Tool %s is expired but not properly shut down yet, skipping file archive",
            tool,
        )
        return

    # Get a special ldap session with read/write permissions
    novaadmin_ds = _open_ldap(
        conf["archive"]["ldap_uri"],
        conf["archive"]["ldap_bind_dn"],
        conf["archive"]["ldap_bind_pass"],
    )

    # Doublecheck that our creds are working and we should really delete this
    disabled_tools = _disabled_datestamps(novaadmin_ds, project)
    if tool not in disabled_tools:
        LOG.warning(
            "Asked to delete %s but can't confirm that it's disabled.", tool
        )
        return

    tool_dn = "cn=%s.%s,ou=servicegroups,dc=wikimedia,dc=org" % (project, tool)
    tool_user_dn = (
        "uid=%s.%s,ou=people,ou=servicegroups,dc=wikimedia,dc=org"
        % (
            project,
            tool,
        )
    )

    # First, remove references to this tool_user_dn in other tools
    tool_base_dn = "ou=servicegroups,dc=wikimedia,dc=org"
    LOG.info("Removing ldap references to %s", tool_user_dn)
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
    LOG.info("Removing ldap entry for %s", tool_user_dn)
    novaadmin_ds.delete_s(tool_user_dn)
    LOG.info("Removing ldap entry for %s", tool_dn)
    novaadmin_ds.delete_s(tool_dn)
    novaadmin_ds.unbind()
    set_step_complete(conf, tool, "ldap_deleted")


def _tool_dir(conf, tool, project):
    base_dir = conf["archive"]["base_dir_%s" % project]
    tool_dir = os.path.join(base_dir, tool)
    return tool_dir


def _tool_archive_file(conf, tool, project):
    archive_dir = conf["archive"]["archive_dir_%s" % project]
    archivefile = os.path.join(archive_dir, "%s.tgz" % tool)
    return archivefile


def _archive_home(conf, tool, project):
    """Make a tarball of the tool's project dir and delete the project dir."""
    tool_dir = _tool_dir(conf, tool, project)

    if not _is_ready_for_archive_and_delete(conf, tool, project):
        LOG.info(
            "Tool %s is expired but not properly shut down yet, skipping file archive",
            tool,
        )
        return

    if not os.path.exists(tool_dir):
        # nothing to archive
        return

    archivefile = _tool_archive_file(conf, tool, project)
    args = ["tar", "-cpzf", archivefile, tool_dir]
    rval = subprocess.call(args)
    if rval:
        LOG.info(
            "Failed to archive %s with exit code %s. Command was: %s",
            tool,
            rval,
            " ".join(args),
        )
        return False
    else:
        LOG.info("Archived %s to %s", tool_dir, archivefile)

    LOG.info("Archive complete; removing %s", tool_dir)

    # We need to do some special magic to get replica.my.cnf out of the way;
    #  otherwise the rmtree below will fail.
    db_conf = os.path.join(tool_dir, REPLICA_CONF)
    subprocess.check_output(["chattr", "-i", db_conf])
    shutil.rmtree(tool_dir)
    LOG.info("removed %s", tool_dir)
    set_step_complete(conf, tool, "home_archived")


def crontab(conf):
    if conf["crontab"]["hostname_substring"] not in socket.gethostname():
        LOG.error("This command can only be run on an sgecron node")
        exit(3)

    ds = _open_ldap()
    reconcile_crontabs(
        conf, _disabled_datestamps(ds, conf["default"]["projectname"])
    )

    # The cron server happens to also be a submit host, so it's a good place
    #  to run qdel:
    disabled_tools = _disabled_datestamps(ds, conf["default"]["projectname"])
    for tool in disabled_tools:
        _kill_grid_jobs(tool)


def gridengine(conf):
    if conf["gridengine"]["hostname_substring"] not in socket.gethostname():
        LOG.error("This command can only be run on a gridengine master node")
        exit(2)

    ds = _open_ldap()
    disabled_tools = _disabled_datestamps(ds, conf["default"]["projectname"])
    for tool in disabled_tools:
        _remove_service_manifest(tool)
        # we don't actually kill jobs here because we can't run qdel on the grid master.
        # that job is left to the cron host (where we /can/ run qdel.)
    reconcile_grid_quotas(conf, disabled_tools)


def archive(conf):
    if conf["archive"]["hostname_substring"] not in socket.gethostname():
        LOG.error("This command can only be run on the toolforge nfs server")
        exit(4)

    ds = _open_ldap()
    for project in [
        project.strip()
        for project in conf["archive"]["all_projects_on_server"].split(",")
    ]:
        disabled_tools = _disabled_datestamps(ds, project)
        for tool in disabled_tools:
            _uid, datestamp = disabled_tools[tool]
            if _is_expired(
                datestamp, int(conf["default"]["archive_after_days"])
            ):
                if not _is_ready_for_archive_and_delete(conf, tool, project):
                    LOG.info(
                        "Tool %s is expired but not shut down yet. Postponing archive step.",
                        tool,
                    )
                    continue
                else:
                    LOG.info("Tool %s is expired; archiving", tool)

                _archive_home(conf, tool, project)
                _delete_ldap_entries(conf, tool, project)


def set_step_complete(conf, tool, step, state=True):
    if state:
        stateval = 1
    else:
        stateval = 0

    connection = pymysql.connect(
        host=conf["database"]["db_host"],
        user=conf["database"]["db_username"],
        password=conf["database"]["db_password"],
        database=conf["database"]["db_name"],
    )
    query = (
        f"INSERT INTO toolstate (toolname, `{step}`) "
        f"VALUES ('{tool}', {stateval}) "
        f"ON DUPLICATE KEY UPDATE `{step}`={stateval};"
    )

    with connection.cursor() as cursor:
        cursor.execute(query)

    connection.close()


def get_step_complete(conf, tool, step):
    connection = pymysql.connect(
        host=conf["database"]["db_host"],
        user=conf["database"]["db_username"],
        password=conf["database"]["db_password"],
        database=conf["database"]["db_name"],
    )
    query = "select `%s` from toolstate where toolname='%s'" % (step, tool)
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
    connection.close()

    if rows and rows[0][step]:
        return True

    return False


def archive_dbs(conf):
    if conf["archivedbs"]["hostname_substring"] not in socket.gethostname():
        LOG.error(
            "This command can only be run on a host that matches %s",
            conf["archivedbs"]["hostname_substring"],
        )
        exit(5)

    ds = _open_ldap()
    disabled_tools = _disabled_datestamps(ds, conf["default"]["projectname"])
    for tool in disabled_tools:
        uid, datestamp = disabled_tools[tool]
        if _is_expired(datestamp, int(conf["default"]["archive_after_days"])):
            tool_home = os.path.join(TOOL_HOME_DIR, tool)
            cron_archive = os.path.join(tool_home, DISABLED_CRON_NAME)

            if (
                not get_step_complete(conf, tool, "kubernetes_disabled")
                or not get_step_complete(conf, tool, "grid_disabled")
                or not os.path.isfile(cron_archive)
            ):
                LOG.info(
                    "Tool %s is expired but not properly shut down yet", tool
                )
                continue
            LOG.info("Archiving databases for %s", tool)

            db_conf = os.path.join(TOOL_HOME_DIR, tool, REPLICA_CONF)
            if not os.path.isfile(db_conf):
                # No replica.my.cnf so nothing to do
                set_step_complete(conf, tool, "db_disabled")
                continue

            dbconfig = configparser.ConfigParser()
            dbconfig.read(db_conf)
            connection = pymysql.connect(
                host="tools.db.svc.wikimedia.cloud",
                user=dbconfig["client"]["user"].strip("'"),
                password=dbconfig["client"]["password"].strip("'"),
            )

            with connection.cursor() as cursor:
                cursor.execute(
                    "SHOW databases LIKE '%s__%%';"
                    % dbconfig["client"]["user"].strip("'")
                )
                dbs = cursor.fetchall()

            for db in dbs:
                fname = os.path.join(TOOL_HOME_DIR, tool, "%s.mysql" % db[0])
                LOG.info(
                    "Archiving databases %s for %s to %s", db[0], tool, fname
                )
                LOG.info("Dumping %s to %s", db[0], fname)
                with open(fname, "w") as f:
                    args = [
                        "mysqldump",
                        "-u",
                        dbconfig["client"]["user"].strip("'"),
                        "--password=%s"
                        % dbconfig["client"]["password"].strip("'"),
                        "--quick",
                        "--max_allowed_packet=1G",
                        db[0],
                    ]
                    rval = subprocess.call(args, stdout=f)
                    if rval != 0:
                        LOG.error(
                            "Failed to dump db %s for tool %s", db[0], tool
                        )
                        # Something went wrong; that probably means the table
                        # is undumpable We're going to be bold and just drop
                        # it.

                LOG.info("Dropping db %s for tool %s", db[0], tool)
                with connection.cursor() as cursor:
                    # This looks a bit unsafe.. but it's executed as the credentials of the tool
                    cursor.execute("DROP database `%s`;" % db[0])

            # Mark us as done with databases
            set_step_complete(conf, tool, "db_disabled")

            connection.close()


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
        "been disabled for more than %s days"
        % config["default"]["archive_after_days"],
    )
    sp_archivedbs.set_defaults(func=archive_dbs)

    args = parser.parse_args()

    if "func" in args:
        args.func(config)
    else:
        parser.print_help()
