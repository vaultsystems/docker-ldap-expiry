#!/usr/bin/python
# LDAP expiry script written by Brad Marshall <brad.marshall@vaultsystems.com.au> 20180214

import time
import datetime
import ldap
import logging
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument("--log", "-l", type=str, default="INFO", help="Logging level")
parser.add_argument("--oneshot", "-o", default=False, help="Run once rather than daemon", action='store_true')
args = parser.parse_args()

loglevel = args.log
numeric_level = getattr(logging, args.log.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)

# Define base variables
searchScope = ldap.SCOPE_SUBTREE
retrieveAttributes = ['*','+']
searchFilter = "(objectclass=inetOrgPerson)"
dateformat = '%Y%m%d%H%M%S'
idletime = datetime.timedelta(days=30)
ldapurl = os.environ.get('LDAPURL','ldap://localhost')
ldapbasedn = os.environ.get('LDAPBASEDN','dc=example,dc=com')
ldapbinddn = os.environ.get('LDAPBINDDN','cn=admin,dc=example,dc=com')
ldapbindcreds = os.environ.get('LDAPBINDCREDS','admin')
sleeptime = 3600

logging.basicConfig(
    level=numeric_level,
    format="%(asctime)s:%(levelname)s:ldap-expiry:%(message)s"
)

logger = logging.getLogger("ldap_expiry")

def expire_accounts():
    # Try to bind to ldap
    try:
        l = ldap.initialize(ldapurl)
        l.simple_bind_s(ldapbinddn,ldapbindcreds)
    except ldap.LDAPError, e:
        logger.error("LDAP Bind failed: %s" % (e))
        return(False)
    
    # Try to do a ldap search for all users
    try:
        ldap_result_id = l.search(ldapbasedn, searchScope, searchFilter, retrieveAttributes)
    except ldap.LDAPError, e:
        logger.error("LDAP search failed: %s"  % (e))
        return(False)
    
    # Grab all the ldap search results
    result_set = []
    while l:
        result_type, result_data = l.result(ldap_result_id, 0)
        if (result_data == []):
            break
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
                result_set.append(result_data)
    
    # Loop over all the results
    for res in result_set:
        dn = res[0][0]
        # Check if the user account is locked
        try:
            accountlockout = res[0][1]['pwdAccountLockedTime'][0]
        except:
            accountlockout = False

        try:
            # Grab the last time this user authed
            timestr = res[0][1]["authTimestamp"][0][:-1]
        except KeyError, e:
            timestr = res[0][1]["createTimestamp"][0][:-1]
     
        # Compare the time the user last authed to the allowed idle time
        timestamp = datetime.datetime.strptime(timestr, dateformat)
        tsnow = datetime.datetime.now()
        authtimediff = tsnow - timestamp
        # If we authed more than the allowed idle time ...
        if authtimediff > idletime:
            # .. and the account is not locked out
            if not accountlockout:
                logger.info("%s is over idle time since last auth - locking account" % (dn))
                # Lock the account now
                locktime = tsnow.strftime(dateformat)
                locktime+="Z"
                mod_list = [(ldap.MOD_ADD, 'pwdAccountLockedTime', locktime)]
                try:
                    lmod = ldap.initialize(ldapurl)
                    lmod.simple_bind_s(ldapbinddn,ldapbindcreds)
                    lmod.modify_s(dn, mod_list)
                    lmod.unbind_s()
                except ldap.LDAPError, e:
                    logger.error("LDAP modification to lock account for %s failed: %s" % (dn, e))
            # if the account is already locked out, no need to lock it
            else:
                logger.debug("%s is already locked out" % (dn))
            # else this user isn't idle
        else:
            logger.debug("%s isn't idle" % (dn))

def main():
    if args.oneshot:
        expire_accounts()
    else:
        while 1:
            logger.info("Starting expiry loop")
            expire_accounts()
            logger.info("Finished expiry loop")
            time.sleep(sleeptime)

if __name__ == "__main__":
    main()

