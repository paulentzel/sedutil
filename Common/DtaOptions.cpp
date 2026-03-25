/* C:B**************************************************************************
This software is Copyright 2014-2017 Bright Plaza Inc. <drivetrust@drivetrust.com>

This file is part of sedutil.

sedutil is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sedutil is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sedutil.  If not, see <http://www.gnu.org/licenses/>.

 * C:E********************************************************************** */
#include "os.h"
#include "DtaOptions.h"
#include "DtaLexicon.h"
#include "Version.h"
void usage()
{
    printf("sedutil v%s Copyright 2014-2017 Bright Plaza Inc. <drivetrust@drivetrust.com>\n", GIT_VERSION);
    printf("a utility to manage self encrypting drives that conform\n");
    printf("to the TCG Enterprise, Opal, Opalite and Pyrite SSC specs\n");
    printf("\n");
    printf("General Usage:                  (see readme for extended commandset)\n");
    printf("sedutil-cli [-vnlx] [-a=auth] [-t=n] [-ds=x,y,z] [-sp=sp] <action> [options] <device>\n");
    printf("-v (optional)                   increase verbosity, one to four v's\n");
    printf("-n (optional)                   no password hashing. Passwords will be sent in clear text!\n");
    printf("-l (optional)                   log style output to stderr only\n");
    printf("-x (optional)                   use a transaction\n");
    printf("-ro (optional)                  use read only session(s)\n");
    printf("-c=comID (optional)             select a comID value: offset from base, absolute, or dynamic\n");
    printf("                                examples: -c=+1 (offset), -c=0x1000 (absolute), -c=d (dynamic)\n");
    printf("-a=authortity (optional)        specify an authority instead of the default for the action\n");
    printf("                                Authorities are Admin[1..n], User[1..n], Admins, SID, PSID, Anybody, or Anonymous\n");
    printf("                                This option is not supported for all actions.\n");
    printf("-t=timeout (optional)           specify a session timeout value to be sent with the Start Session\n");
    printf("-ds=x,y,z (optional)            specify datastore sizes for activate\n");
    printf("-sp=sp (optional)               specify a security protocol to access, Admin or Locking\n");
    printf("-o=output_file                  specify the results be sent to a file (readDataStore and readMBR only)\n");
    printf("\n");
    printf("actions:\n");
    printf("--scan\n");
    printf("                                Scans the devices on the system \n");
    printf("                                identifying Opal compliant devices \n");
    printf("--query <device>\n");
    printf("                                Display the Discovery 0 response of a device\n");
    printf("--isValidSED <device>\n");
    printf("                                Verify whether the given device is SED or not\n");
    printf("--listLockingRanges <password> <device>\n");
	printf("                                List all Locking Ranges\n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
    printf("--listLockingRange <0...n> <password> <device>\n");
	printf("                                List all Locking Ranges\n");
	printf("                                0 = GLobal 1..n  = LRn \n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
    printf("--rekeyLockingRange <0...n> <password> <device>\n");
	printf("                                0 = GLobal 1..n  = LRn \n");
	printf("                                Rekey Locking Range\n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
    printf("--setBandsEnabled <password> <device>\n");
	printf("                                Set Enabled for all Locking Ranges\n");
	printf("                                (password = \"\" for MSID) \n");
    printf("--setBandEnabled <0...n> <password> <device>\n");
	printf("                                Set Enabled for Locking Range[n]\n");
	printf("                                (password = \"\" for MSID) \n");
    printf("--eraseLockingRange <0...n> <password> <device>\n");
	printf("                                Erase a Locking Range\n");
	printf("                                0 = GLobal 1..n  = LRn \n");
    printf("--setupLockingRange <0...n> <RangeStart> <RangeLength> <password> <device>\n");
	printf("                                Setup a new Locking Range\n");
	printf("                                0 = GLobal 1..n  = LRn \n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
	printf("--initialSetup <SIDpassword> <device>\n");
	printf("                                Setup the device for use with sedutil\n");
	printf("                                <SIDpassword> is new SID and Admin1 password\n");
	printf("--setSIDPassword <SIDpassword> <newSIDpassword> <device> \n");
	printf("                                Change the SID password\n");
    printf("--takeOwnership <newSIDpassword> <device> \n");
    printf("                                Change the SID password using the existing password\n");
	printf("--setAdmin1Pwd <Admin1password> <newAdmin1password> <device> \n");
	printf("                                Change the Admin1 password in the LockingSP\n");
	printf("--setPassword <oldpassword, \"\" for NULL> <userid> <newpassword> <device> \n");
	printf("                                Change password for userid:\n");
	printf("                                Enteprise: \"EraseMaster\" or \"BandMaster<n>\"\n");
	printf("                                Opal: \"Admin<n>\" or \"User<n>\"\n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
    printf("                                default security protocol is Locking, over-ride with -sp option\n");
    printf("--enableUser <password> <user> <device>\n");
    printf("                                enable a user, user = Admin[2...n] or User[2...n]\n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
    printf("                                default security protocol is Locking, over-ride with -sp option\n");
	printf("--setLockingRange <0...n> <RW|RO|WO|LK|+R|-R> <Admin1password> <device> \n");
	printf("                                Set the status of a Locking Range\n");
	printf("                                0 = GLobal 1..n  = LRn \n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
	printf("--enableLockingRange <0...n> <Admin1password> <device> \n");
	printf("                                Enable a Locking Range\n");
	printf("                                0 = GLobal 1..n  = LRn \n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
	printf("--disableLockingRange <0...n> <Admin1password> <device> \n");
	printf("                                Disable a Locking Range\n");
	printf("                                0 = GLobal 1..n  = LRn \n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
	printf("--setMBREnable <on|off> <Admin1password> <device> \n");
	printf("                                Enable|Disable MBR shadowing \n");
	printf("--setMBRDone <on|off> <Admin1password> <device> \n");
	printf("                                set|unset MBRDone\n");
	printf("--loadPBAimage <Admin1password> <file> <device> \n");
	printf("                                Write <file> to MBR Shadow area\n");
	printf("--readMBR <Admin1password> <offset> <count> <device>\n");
	printf("                                Print MBR data starting at offset for count bytes.\n");
    printf("--clearDoneOnReset <Admin1password> <D|E> <device>\n");
    printf("                                Enable or Disable clearing of MBR Done on TperReset, D = disable, E = enable\n");
	printf("--loadDataStore <Admin1password> <table> <offset> <count> <file> <device>\n");
	printf("                                Load data from a file into the Datastore table.\n");
	printf("                                count is maxiumum bytes to write, 0 for whole file.\n");
	printf("                                table selects the DataStore table, 1 if no additional tables.\n");
	printf("--readDataStore <Admin1password> <table> <offset> <count> <device>\n");
	printf("                                Print DataStore data starting at offset for count bytes.\n");
	printf("                                table selects the DataStore table, 1 if no additional tables.\n");
    printf("--activateLockingSP <SIDpassword> <device>\n");
    printf("                                Activate the LockingSP. Admin1 password\n");
    printf("                                in LockingSP will be set to SIDpassword.\n");
    printf("--assign <namespace> <rangeStart> <rangeLength> <Admin1Password> <device>\n");
    printf("                                Assign a locking range for a namespace\n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
    printf("--deassign <1...n> <keepGlobalKey> <Admin1password> <device>\n");
    printf("                                1...n = LRn, keepGlobalKey = T or F\n");
    printf("                                default authority is Admin1, over-ride with -a option\n");
    printf("--revertTPer <password> <device>\n");
    printf("                                set the device back to factory defaults \n");
	printf("                                This **ERASES ALL DATA** \n");
    printf("                                Default authority is SID, over-ride with -a option\n");
    printf("--revertSP <SP> <authority> <password> <keep> <device>\n");
    printf("                                revert the selected SP to factory state\n");
    printf("                                SP is Admin or Locking, keep is T or F\n");
    printf("                                keep = T only preserves the Global range key\n");
	printf("--revertLockingSP <Admin1password> <device>\n");
	printf("                                deactivate the Locking SP, erase everything\n");
	printf("--revertNoErase <Admin1password> <device>\n");
	printf("                                deactivate the Locking SP without erasing the data\n");
	printf("                                on GLOBAL RANGE *ONLY*\n");
	printf("--PSIDrevert <PSID> <device>\n");
	printf("--yesIreallywanttoERASEALLmydatausingthePSID <PSID> <device>\n");
	printf("                                revert the device using the PSID *ERASING*\n");
	printf("                                *ALL* the data\n");
	printf("--PSIDrevertAdminSP <PSID> <device>\n");
	printf("                                Alike to PSIDrevert, but on Enterprise calls\n");
	printf("                                AdminSP->Revert instead of ThisSP->RevertSP\n");
    printf("--printDefaultPassword <device>\n");
    printf("                                print MSID \n");
    printf("--printTables <SP> <password> <level> <device>\n");
    printf("                                get and print table values for a SP\n");
    printf("                                SP is Admin or Locking\n");
    printf("                                use \"\" as password for MSID.\n");
    printf("                                level 0 = tables, 1 = tables & ACL, 2 = details, 3 = debug\n");
    printf("--enableTperReset <SIDpassword> <D|E> <device>\n");
    printf("                                Set Enable TPer Reset, D = disable, E = enable\n");
    printf("--tperReset <device>\n");
    printf("                                Send TPER_RESET to device\n");
    printf("--stackReset <device>\n");
    printf("                                Send a STACK_RESET for the base ComID, over-ride with the -c option\n");
    printf("--verifyComIDValid <device>\n");
    printf("                                Send a VERIFY_COMID_VALID for the base ComID, over-ride with the -c option\n");
    printf("--getRandom <size> <password> <device>\n");
    printf("                                Generate a random byte sequence of <size> bytes\n");
    printf("                                Default SP is Admin, default authority is Anybody\n");
    printf("\n");
    printf("Examples \n");
    printf("sedutil-cli --scan \n");
	printf("sedutil-cli --query %s \n", DEVICEEXAMPLE);
	printf("sedutil-cli --yesIreallywanttoERASEALLmydatausingthePSID <PSIDNODASHED> %s \n", DEVICEEXAMPLE);
	printf("sedutil-cli --initialSetup <newSIDpassword> %s \n", DEVICEEXAMPLE);
    return;
}

uint8_t DtaOptions(int argc, char * argv[], DTA_OPTIONS * opts)
{
    memset(opts, 0, sizeof (DTA_OPTIONS));
    uint16_t loggingLevel = 3;
	uint8_t baseOptions = 2; // program and option
    CLog::Level() = CLog::FromInt(loggingLevel);
    RCLog::Level() = RCLog::FromString("INFO");
    if (2 > argc) {
        usage();
		return DTAERROR_INVALID_COMMAND;
    }
	for (uint8_t i = 1; i < argc; i++) {
		if (!(strcmp("-h", argv[i])) || !(strcmp("--help", argv[i]))) {
			usage();
			return DTAERROR_INVALID_COMMAND;
		}
		else if ('v' == argv[i][1])
		{
			baseOptions += 1;
			loggingLevel += (uint16_t)(strlen(argv[i]) - 1);
			if (loggingLevel > 8) loggingLevel = 8;
			CLog::Level() = CLog::FromInt(loggingLevel);
			RCLog::Level() = RCLog::FromInt(loggingLevel);
			LOG(D) << "Log level set to " << CLog::ToString(CLog::FromInt(loggingLevel));
			LOG(D) << "sedutil version : " << GIT_VERSION;
		}
		else if (!(strcmp("-n", argv[i]))) {
                        baseOptions += 1;
			opts->no_hash_passwords = true;
			LOG(D) << "Password hashing is disabled";
                }
		else if (!strcmp("-l", argv[i])) {
			baseOptions += 1;
			opts->output_format = sedutilNormal;
			outputFormat = sedutilNormal;
		}
        else if (!strncmp("-a=", argv[i], 3)) {
            ++baseOptions;
            strncpy(opts->authority, &argv[i][3], sizeof(opts->authority) - 1);
            LOG(D) << "Default authority over-ride, using " << opts->authority;
        }
        else if (!strncmp("-sp=", argv[i], 4)) {
            ++baseOptions;
            strncpy(opts->sp, &argv[i][4], sizeof(opts->sp) - 1);
            LOG(D) << "Default security protcol over-ride, using " << opts->sp;
        }
        else if (!strcmp("-x", argv[i])) {
            baseOptions += 1;
            opts->useTransaction = true;
        }
        else if (!strcmp("-xa", argv[i])) {
            baseOptions += 1;
            opts->useTransaction = true;
            opts->abort = true;
        }
        else if (!strcmp("-ro", argv[i])) {
            baseOptions += 1;
            opts->useReadOnlySession = true;
        }
        else if (!strncmp("-ds=", argv[i], 4)) {
            ++baseOptions;
            char* ptr = &argv[i][4];
            for (opts->datastoreCount = 0; (*ptr != 0) && (opts->datastoreCount < 16);
                 opts->datastoreCount++) {
                if ((sscanf(ptr, "%i", &opts->datastoreSizes[opts->datastoreCount])) == 0) {
                    break;
                }
                for (int j = 0; j < 256; j++, ptr++) {
                    if (*ptr == 0) {
                        break;
                    }
                    if ((*ptr == ',')) {
                        ++ptr;
                        break;
                    }
                }
            }
        } else if (!strncmp("-tt", argv[i], 3)) {
            ++baseOptions;
            opts->testTimeout = 1;
            if (argv[i][3] == '=') {
                opts->delay = atoi(&argv[i][4]);
                LOG(D) << "Configured to delay after open session for "
                       << opts->delay << " milliseconds";
            } else {
                LOG(D) << "Configured to test timeout";
            }
        }
        else if (!strcmp("-top", argv[i])) {
            ++baseOptions;
            opts->testOversizePacket = 1;
            LOG(D) << "Configured to test oversize packet";
        }
        else if (!strncmp("-t=", argv[i], 3)) {
            ++baseOptions;
            opts->useSessionTimeout = true;
            opts->timeout = atoi(&argv[i][3]);
            LOG(D) << "session timeout set to " << opts->timeout;
        }
        else if (!strncmp("-c=", argv[i], 3)) {
            ++baseOptions;
            if ((argv[i][3] == 'd') || (argv[i][3] == 'D')) {
                opts->comID_Option = ComID_Dynamic;
            } else {
                if (argv[i][3] == '+') {
                    opts->comID_Option = ComID_Offset;
                } else {
                    opts->comID_Option = ComID_Select;
                }
                if (sscanf(&argv[i][3], "%i", &(opts->comID_Value)) != 1) {
                    LOG(E) << "Invalid ComID option value";
                    return DTAERROR_INVALID_COMMAND;
                }
            }
        }
        else if (!strncmp("-o=", argv[i], 3)) {
          ++baseOptions;
          opts->outputFilePtr = argv[i] + 3;
        }
        else if (!strncmp("-mt=", argv[i], 4)) {
            ++baseOptions;
            opts->sendRetries = atoi(&argv[i][4]);
            LOG(D) << "multi-thread retry count set to " << opts->sendRetries;
        }
        else if (!(('-' == argv[i][0]) && ('-' == argv[i][1])) && (0 == opts->action)) {
			LOG(E) << "Argument " << (uint16_t) i << " (" << argv[i] << ") should be a command";
			return DTAERROR_INVALID_COMMAND;
		}
		BEGIN_OPTION(initialSetup, 2) OPTION_IS(password) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(setSIDPassword, 3) OPTION_IS(password) OPTION_IS(newpassword)
			OPTION_IS(device) END_OPTION
		BEGIN_OPTION(setup_SUM, 6)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(lrstart)
			OPTION_IS(lrlength)
			OPTION_IS(password)
			OPTION_IS(newpassword)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(setAdmin1Pwd, 3) OPTION_IS(password) OPTION_IS(newpassword)
			OPTION_IS(device) END_OPTION
		BEGIN_OPTION(loadPBAimage, 3) OPTION_IS(password) OPTION_IS(pbafile)
			OPTION_IS(device) END_OPTION
		BEGIN_OPTION(readMBR, 4)
			OPTION_IS(password)
			OPTION_IS(offset)
			OPTION_IS(count)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(loadDataStore, 6)
			OPTION_IS(password)
			OPTION_IS(lrstart)
			OPTION_IS(offset)
			OPTION_IS(count)
			OPTION_IS(pbafile)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(readDataStore, 5)
			OPTION_IS(password)
			OPTION_IS(lrstart)
			OPTION_IS(offset)
			OPTION_IS(count)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(revertTPer, 2) OPTION_IS(password) OPTION_IS(device) END_OPTION
        BEGIN_OPTION(revertSP, 5)
            OPTION_IS(spindex)
            OPTION_IS(userid)
            OPTION_IS(password)
            TESTARG(t, lockingstate, 1)
            TESTARG(T, lockingstate, 1)
            TESTARG(f, lockingstate, 0)
            TESTARG(F, lockingstate, 0)
            TESTFAIL("Invalid value for keep argument (T or F)")
            OPTION_IS(device)
            END_OPTION
		BEGIN_OPTION(revertNoErase, 2) OPTION_IS(password) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(PSIDrevert, 2) OPTION_IS(password) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(PSIDrevertAdminSP, 2) OPTION_IS(password) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(yesIreallywanttoERASEALLmydatausingthePSID, 2) OPTION_IS(password)
			OPTION_IS(device) END_OPTION
		BEGIN_OPTION(enableuser, 3) OPTION_IS(password) OPTION_IS(userid)
			OPTION_IS(device) END_OPTION
		BEGIN_OPTION(activateLockingSP, 2) OPTION_IS(password) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(activateLockingSP_SUM, 4)
//			TESTARG_RANGE(lockingrange, 0, 255, "Invalid Locking Range (0-47 or 255 for all)")
                        OPTION_IS(lockingrange)
                        TESTARG_RANGE(policy, 0, 1, "Invalid policy (0-1)")
			OPTION_IS(password) OPTION_IS(device) END_OPTION
                BEGIN_OPTION(reactivateLockingSP_SUM, 4)
                        OPTION_IS(lockingrange)
                        TESTARG_RANGE(policy, 0, 1, "Invalid policy (0-1)")
                        OPTION_IS(password) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(eraseLockingRange_SUM, 3)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(password) OPTION_IS(device) END_OPTION
        BEGIN_OPTION(lock_SUM, 3)
            TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
            OPTION_IS(password)
            OPTION_IS(device)
            END_OPTION
        BEGIN_OPTION(printTables, 4)
            OPTION_IS(userid)
            OPTION_IS(password)
            TESTARG(0, level, 0)
            TESTARG(1, level, 1)
            TESTARG(2, level, 2)
            TESTARG(3, level, 3)
            TESTFAIL("Invalid level (0-3)")
            OPTION_IS(device) END_OPTION
		BEGIN_OPTION(query, 1) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(scan, 0)  END_OPTION
		BEGIN_OPTION(isValidSED, 1) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(eraseLockingRange, 3)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(takeOwnership, 2) OPTION_IS(password) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(revertLockingSP, 2) OPTION_IS(password) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(setPassword, 4) OPTION_IS(password) OPTION_IS(userid)
			OPTION_IS(newpassword) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(setPassword_SUM, 4) OPTION_IS(password) OPTION_IS(userid)
			OPTION_IS(newpassword) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(validatePBKDF2, 0) END_OPTION
		BEGIN_OPTION(setMBREnable, 3)
			TESTARG(ON, mbrstate, 1)
			TESTARG(on, mbrstate, 1)
			TESTARG(off, mbrstate, 0)
			TESTARG(OFF, mbrstate, 0)
			TESTFAIL("Invalid setMBREnable argument not <on|off>")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(setMBRDone, 3)
			TESTARG(ON, mbrstate, 1)
			TESTARG(on, mbrstate, 1)
			TESTARG(off, mbrstate, 0)
			TESTARG(OFF, mbrstate, 0)
			TESTFAIL("Invalid setMBRDone argument not <on|off>")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(setLockingRange, 4)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			TESTARG(RW, lockingstate, OPAL_LOCKINGSTATE::READWRITE)
			TESTARG(rw, lockingstate, OPAL_LOCKINGSTATE::READWRITE)
			TESTARG(RO, lockingstate, OPAL_LOCKINGSTATE::READONLY)
			TESTARG(ro, lockingstate, OPAL_LOCKINGSTATE::READONLY)
            TESTARG(WO, lockingstate, OPAL_LOCKINGSTATE::WRITEONLY)
            TESTARG(wo, lockingstate, OPAL_LOCKINGSTATE::WRITEONLY)
			TESTARG(LK, lockingstate, OPAL_LOCKINGSTATE::LOCKED)
			TESTARG(lk, lockingstate, OPAL_LOCKINGSTATE::LOCKED)
            TESTARG(+R, lockingstate, OPAL_LOCKINGSTATE::ENABLERESET)
            TESTARG(+r, lockingstate, OPAL_LOCKINGSTATE::ENABLERESET)
            TESTARG(-R, lockingstate, OPAL_LOCKINGSTATE::DISABLERESET)
            TESTARG(-r, lockingstate, OPAL_LOCKINGSTATE::DISABLERESET)
			TESTFAIL("Invalid locking state <ro|rw|lk|+r|-r>")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(setLockingRange_SUM, 4)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			TESTARG(RW, lockingstate, OPAL_LOCKINGSTATE::READWRITE)
			TESTARG(rw, lockingstate, OPAL_LOCKINGSTATE::READWRITE)
			TESTARG(RO, lockingstate, OPAL_LOCKINGSTATE::READONLY)
			TESTARG(ro, lockingstate, OPAL_LOCKINGSTATE::READONLY)
            TESTARG(WO, lockingstate, OPAL_LOCKINGSTATE::WRITEONLY)
            TESTARG(wo, lockingstate, OPAL_LOCKINGSTATE::WRITEONLY)
			TESTARG(LK, lockingstate, OPAL_LOCKINGSTATE::LOCKED)
			TESTARG(lk, lockingstate, OPAL_LOCKINGSTATE::LOCKED)
			TESTFAIL("Invalid locking state <ro|rw|lk>")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(enableLockingRange, 3)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
        BEGIN_OPTION(enableLockingRange_SUM, 4)
            TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
            TESTARG(RW, lockingstate, OPAL_LOCKINGSTATE::READWRITE)
            TESTARG(rw, lockingstate, OPAL_LOCKINGSTATE::READWRITE)
            TESTARG(R, lockingstate,  OPAL_LOCKINGSTATE::READONLY)
            TESTARG(r, lockingstate,  OPAL_LOCKINGSTATE::READONLY)
            TESTARG(W, lockingstate,  OPAL_LOCKINGSTATE::LOCKED)
            TESTARG(w, lockingstate,  OPAL_LOCKINGSTATE::LOCKED)
            TESTARG(D, lockingstate,  OPAL_LOCKINGSTATE::DISABLED)
            TESTARG(d, lockingstate,  OPAL_LOCKINGSTATE::DISABLED)
            TESTFAIL("Invalid locking state <rw|r|w|d>")
            OPTION_IS(password)
            OPTION_IS(device)
            END_OPTION
		BEGIN_OPTION(disableLockingRange, 3)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(setupLockingRange, 5)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(lrstart)
			OPTION_IS(lrlength)
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(setupLockingRange_SUM, 5)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(lrstart)
			OPTION_IS(lrlength)
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(readonlyLockingRange, 3)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(listLockingRanges, 2)
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(listLockingRange, 3)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(rekeyLockingRange, 3)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(setBandsEnabled, 2)
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
		BEGIN_OPTION(setBandEnabled, 3)
			TESTARG_RANGE(lockingrange, 0, 47, "Invalid Locking Range (0-47)")
			OPTION_IS(password)
			OPTION_IS(device)
			END_OPTION
        BEGIN_OPTION(assign, 5)
            OPTION_IS(lockingrange)
            OPTION_IS(lrstart)
            OPTION_IS(lrlength)
            OPTION_IS(password)
            OPTION_IS(device)
            END_OPTION
        BEGIN_OPTION(deassign, 4)
            OPTION_IS(lockingrange)
            TESTARG(t, lockingstate, 1)
            TESTARG(T, lockingstate, 1)
            TESTARG(f, lockingstate, 0)
            TESTARG(F, lockingstate, 0)
            TESTFAIL("Invalid value for keep argument (T or F)")
            OPTION_IS(password)
            OPTION_IS(device)
            END_OPTION
        BEGIN_OPTION(assign_SUM, 5)
            OPTION_IS(lockingrange)
            OPTION_IS(lrstart)
            OPTION_IS(lrlength)
            OPTION_IS(password)
            OPTION_IS(device)
            END_OPTION
        BEGIN_OPTION(featureLock, 4)
            OPTION_IS(lrstart)
            OPTION_IS(lrlength)
            OPTION_IS(password)
            OPTION_IS(device)
            END_OPTION
		BEGIN_OPTION(objDump, 5) i += 4; OPTION_IS(device) END_OPTION
        BEGIN_OPTION(printDefaultPassword, 1) OPTION_IS(device) END_OPTION
		BEGIN_OPTION(rawCmd, 7) i += 6; OPTION_IS(device) END_OPTION
        BEGIN_OPTION(enableTperReset, 3)
            OPTION_IS(password)
            TESTARG(D, lockingstate, OPAL_LOCKINGSTATE::DISABLERESET)
            TESTARG(E, lockingstate, OPAL_LOCKINGSTATE::ENABLERESET)
            TESTFAIL("Invalid option <D|E>")
            OPTION_IS(device)
            END_OPTION
        BEGIN_OPTION(clearDoneOnReset, 3)
            OPTION_IS(password)
            TESTARG(D, lockingstate, OPAL_LOCKINGSTATE::DISABLERESET)
            TESTARG(E, lockingstate, OPAL_LOCKINGSTATE::ENABLERESET)
            TESTFAIL("Invalid option <D|E>")
            OPTION_IS(device)
            END_OPTION
        BEGIN_OPTION(tperReset, 1) OPTION_IS(device) END_OPTION
        BEGIN_OPTION(stackReset, 1) OPTION_IS(device) END_OPTION
        BEGIN_OPTION(verifyComIdValid, 1) OPTION_IS(device) END_OPTION
        BEGIN_OPTION(getACE, 3)
            OPTION_IS(offset)
            OPTION_IS(password)
            OPTION_IS(device)
            END_OPTION
        BEGIN_OPTION(setACE, 4)
            OPTION_IS(offset)
            OPTION_IS(userid)
            OPTION_IS(password)
            OPTION_IS(device)
            END_OPTION
        BEGIN_OPTION(getRandom, 3)
            OPTION_IS(offset)
            OPTION_IS(password)
            OPTION_IS(device)
            END_OPTION
		else {
            LOG(E) << "Invalid command line argument " << argv[i];
			return DTAERROR_INVALID_COMMAND;
        }
    }
    return 0;
}
