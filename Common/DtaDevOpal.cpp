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
/** Device class for Opal 2.0 SSC
 * also supports the Opal 1.0 SSC
 */
#include "os.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include "DtaDevOpal.h"
#include "DtaHashPwd.h"
#include "DtaEndianFixup.h"
#include "DtaStructures.h"
#include "DtaCommand.h"
#include "DtaResponse.h"
#include "DtaSession.h"
#include "DtaHexDump.h"
#include "DtaAnnotatedDump.h"

using namespace std;

DtaDevOpal::DtaDevOpal()
{
}

DtaDevOpal::~DtaDevOpal()
{
}
void DtaDevOpal::init(const char * devref)
{
	uint8_t lastRC;
	DtaDevOS::init(devref);
	if((lastRC = properties()) != 0) { LOG(E) << "Properties exchange failed";}
}

uint8_t DtaDevOpal::initialSetup(const char* password)
{
	LOG(D1) << "Entering initialSetup()";
	uint8_t lastRC;
	if ((lastRC = takeOwnership(password)) != 0) {
		LOG(E) << "Initial setup failed - unable to take ownership";
		return lastRC;
	}
	if ((lastRC = activateLockingSP(password)) != 0) {
		LOG(E) << "Initial setup failed - unable to activate LockingSP";
		return lastRC;
	}
	if ((lastRC = configureLockingRange(0, DTA_DISABLELOCKING, "Admin1", password)) != 0) {
		LOG(E) << "Initial setup failed - unable to configure global locking range";
		return lastRC;
	}
	if ((lastRC = setLockingRange(0, OPAL_LOCKINGSTATE::READWRITE, "Admin1", password)) != 0) {
		LOG(E) << "Initial setup failed - unable to set global locking range RW";
		return lastRC;
	}
	if (!MBRAbsent()) {
		setMBREnable(1, password);
	}

	LOG(I) << "Initial setup of TPer complete on " << dev;
	LOG(D1) << "Exiting initialSetup()";
	return 0;
}

uint8_t DtaDevOpal::setup_SUM(const uint8_t lockingrange, const uint64_t start, const uint64_t length,
                              const char* Admin1Password, const char* password)
{
	LOG(D1) << "Entering setup_SUM()";
	uint8_t lastRC;
	char defaultPW[] = ""; //OPAL defines the default initial User password as 0x00
	std::string userId;
	userId.append("User");
	userId.append(std::to_string(lockingrange + 1)); //OPAL defines LR0 to User1, LR1 to User2, etc.

	//verify opal SUM support and status
	if (!disk_info.Locking || !disk_info.SingleUser)
	{
		LOG(E) << "Setup_SUM failed - this drive does not support LockingSP / SUM";
		return DTAERROR_INVALID_COMMAND;
	}
	if (disk_info.Locking_lockingEnabled && !disk_info.SingleUser_any)
	{
		LOG(E) << "Setup_SUM failed - LockingSP has already been configured in standard mode.";
		return DTAERROR_INVALID_COMMAND;
	}
	//If locking not enabled, run initial setup flow
	if (!disk_info.Locking_lockingEnabled)
	{
		LOG(D1) << "LockingSP not enabled. Beginning initial setup flow.";
		if ((lastRC = takeOwnership(Admin1Password)) != 0) {
			LOG(E) << "Setup_SUM failed - unable to take ownership";
			return lastRC;
		}
		std::vector<uint32_t> ranges(lockingrange);
		if ((lastRC = activateLockingSP_SUM(ranges, 0, Admin1Password)) != 0) {
			LOG(E) << "Setup_SUM failed - unable to activate LockingSP in SUM";
			return lastRC;
		}
		if ((lastRC = setupLockingRange_SUM(lockingrange, start, length, defaultPW)) != 0) {
			LOG(E) << "Setup_SUM failed - unable to setup locking range " << lockingrange << "(" << start << "," << length << ")";
			return lastRC;
		}
	}
	if ((lastRC = eraseLockingRange_SUM("Admin1", lockingrange, Admin1Password)) != 0) {
		LOG(E) << "Setup_SUM failed - unable to erase locking range";
		return lastRC;
	}

	//verify that locking range covers correct LBAs
	lrStatus_t lrStatus;
	if ((lrStatus = getLockingRange_status(lockingrange, Admin1Password)).command_status != 0) {
		LOG(E) << "Setup_SUM failed - unable to query locking range start/size";
		return lrStatus.command_status;
	}
	if (start != lrStatus.start || length != lrStatus.size)
	{
		LOG(D1) << "Incorrect Locking Range " << lockingrange << " start/size. Attempting to correct...";
		if ((lastRC = setupLockingRange_SUM(lockingrange, start, length, defaultPW)) != 0) {
			LOG(E) << "Setup_SUM failed - unable to setup locking range " << lockingrange << "(" << start << "," << length << ")";
			return lastRC;
		}
		LOG(D1) << "Locking Range " << lockingrange << " start/size corrected.";
	}

	//enable and set new password for locking range
	if ((lastRC = setLockingRange_SUM(lockingrange, OPAL_LOCKINGSTATE::READWRITE, defaultPW)) != 0) {
		LOG(E) << "Setup_SUM failed - unable to enable locking range";
		return lastRC;
	}
	if ((lastRC = setNewPassword_SUM(defaultPW, (char *)userId.c_str(), password)) != 0) {
		LOG(E) << "Setup_SUM failed - unable to set new locking range password";
		return lastRC;
	}

	LOG(I) << "Setup of SUM complete on " << dev;
	LOG(D1) << "Exiting setup_SUM()";
	return 0;
}

DtaDevOpal::lrStatus_t DtaDevOpal::getLockingRange_status(const uint8_t lockingrange, 
                                                          const char* password)
{
	uint8_t lastRC;
	lrStatus_t lrStatus;
	LOG(D1) << "Entering DtaDevOpal:getLockingRange_status()";
	vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		lrStatus.command_status = DTAERROR_OBJECT_CREATE_FAILED;
		return lrStatus;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, OPAL_UID::OPAL_ADMIN1_UID)) != 0) {
		delete session;
		lrStatus.command_status = lastRC;
		return lrStatus;
	}
	if (0 != lockingrange) {
		LR[8] = lockingrange & 0xff;
		LR[6] = 0x03;  // non global ranges are 00000802000300nn
	}
	if ((lastRC = getTable(LR, _OPAL_TOKEN::RANGESTART, _OPAL_TOKEN::WRITELOCKED)) != 0) {
		delete session;
		lrStatus.command_status = lastRC;
		return lrStatus;
	}
	if (response.getTokenCount() < 24)
	{
		LOG(E) << "locking range getTable command did not return enough data";
		delete session;
		lrStatus.command_status = DTAERROR_NO_LOCKING_INFO;
		return lrStatus;
	}
	lrStatus.command_status = 0;
	lrStatus.lockingrange_num = lockingrange;
	lrStatus.start = response.getUint64(4);
	lrStatus.size = response.getUint64(8);
	lrStatus.RLKEna = (response.getUint8(12) != 0);
	lrStatus.WLKEna = (response.getUint8(16) != 0);
	lrStatus.RLocked = (response.getUint8(20) != 0);
	lrStatus.WLocked = (response.getUint8(24) != 0);
	LOG(D1) << "Locking Range " << lockingrange << " Begin: " << lrStatus.start << " Length: "
		<< lrStatus.size << " RLKEna: " << lrStatus.RLKEna << " WLKEna: " << lrStatus.WLKEna
		<< " RLocked: " << lrStatus.RLocked << " WLocked: " << lrStatus.WLocked;
	delete session;
	LOG(D1) << "Exiting DtaDevOpal:getLockingRange_status()";
	return lrStatus;
}

uint8_t DtaDevOpal::listLockingRanges(const char* authority, const char* password, const int16_t rangeid)
{
        int firstRange = (int)rangeid;
        int lastRange = (int)rangeid;
	uint8_t lastRC;
	LOG(D1) << "Entering DtaDevOpal:listLockingRanges() " << rangeid;
	vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}

    vector<uint8_t> authorityUID;
	if ((lastRC = getAuth4User(OPAL_UID::OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}
        if (rangeid == -1) {
            vector<uint8_t> table;
            table.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
            for (int i = 0; i < 8; i++) {
                    table.push_back(OPALUID[OPAL_UID::OPAL_LOCKING_INFO_TABLE][i]);
            }
            if ((lastRC = getTable(table, OPAL_TOKEN::MAXRANGES, OPAL_TOKEN::MAXRANGES)) != 0) {
                    delete session;
                    return lastRC;
            }
            if (response.tokenIs(4) != OPAL_TOKEN::DTA_TOKENID_UINT) {
                    LOG(E) << "Unable to determine number of ranges ";
                    delete session;
                    return DTAERROR_NO_LOCKING_INFO;
            }
            firstRange = 0;
            lastRange = (int)response.getUint32(4);
        }

        LOG(I) << "Locking Range Configuration for " << dev;

	if (disk_info.SingleUser_any) {
		// At least one locking range is in single-user mode.  Pull the list and show the ones that are.
		std::vector<uint8_t> table;
		table.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
		for (int i = 0; i < 8; i++) {
			table.push_back(OPALUID[OPAL_UID::OPAL_LOCKING_INFO_TABLE][i]);
		}
		if ((lastRC = getTable(table, (uint32_t)OPAL_TOKEN::SUM_RANGES,
							          (uint32_t)OPAL_TOKEN::SUM_RANGES)) == 0) {
			if ((response.tokenIs(2) == OPAL_TOKEN::STARTNAME) &&
			    (response.getUint32(3) == OPAL_TOKEN::SUM_RANGES)) {
				if (response.tokenIs(4) == OPAL_TOKEN::STARTLIST) {
					// SingleUserModeRanges is a list of UIDs
					int tokenCount = response.getTokenCount();
					bool firstRange = true;

					for (int t = 5; t < tokenCount; t++) {
						uint8_t uid[8];
						if (response.tokenIs(t) != OPAL_TOKEN::DTA_TOKENID_BYTESTRING) {
							break;
						}
						response.getBytes(t, uid);
						uint32_t lr = ((uint32_t)uid[6] << 8) + (uint32_t)uid[7];
						if ((uid[5] == 0x00) && (lr == 1)) {
							lr = 0;
						}
						if ((lr == (uint32_t)rangeid) || (rangeid == -1)) {
							char uidStr[20];
							printBytes(uid, 8, uidStr);
							if (firstRange) {
								LOG(I) << "The following locking ranges are listed as single-user mode:";
								firstRange = false;
							}
							LOG(I) << "  Locking Range UID: " << uidStr << " (LR" << lr << ")";
						}
					}
				} else {
					// SingleUserModeList is a single UID (should be Locking Table UID)
					if (response.tokenIs(4) == OPAL_TOKEN::DTA_TOKENID_BYTESTRING) {
						uint8_t uid[8];
						response.getBytes(4, uid);
						char uidStr[20];
						printBytes(uid, 8, uidStr);
						LOG(I) << "Single User mode for UID: " << uidStr;
					}
				}
			} else {
				LOG(I) << "Single User mode reported enabled, but no locking ranges reported in single user mode.";
			}
		}
	}

	for (int i = firstRange; i <= lastRange; i++){
		if(0 != i) {
                    LR[6] = 0x03;  // non global ranges are 00000802000300nn
                    LR[8] = i & 0xff;
                }
		if ((lastRC = getTable(LR, _OPAL_TOKEN::RANGESTART, (uint32_t)-1)) != 0) {
			delete session;
			return lastRC;
		}

		std::string rangeStart("N/A");
		std::string rangeLength("N/A");
		std::string wle("N/A");
		std::string rle("N/A");
		std::string wl("N/A");
		std::string rl("N/A");
		std::string resets;
		std::string ns("N/A");
		std::string global("N/A");

		int tokenCount = response.getTokenCount();

		for (int t = 2; t < tokenCount; t += 2) {
			if (response.tokenIs(t) != OPAL_TOKEN::STARTNAME) {
				break;
			}
			switch (response.getUint32(++t)) {
			case 3:
				rangeStart = to_string(response.getUint64(++t));
				break;
			case 4:
				rangeLength = to_string(response.getUint64(++t));
				break;
			case 5:
				rle = response.getUint32(++t) ? "Y" : "N";
				break;
			case 6:
				wle = response.getUint32(++t) ? "Y" : "N";
				break;
			case 7:
				rl = response.getUint32(++t) ? "Y" : "N";
				break;
			case 8:
				wl = response.getUint32(++t) ? "Y" : "N";
				break;
			case 9:
				resets.append("  LockOnReset =");
				// the response included the reset list, parse it
				t += 2;		// skip the SOL
				for (; t < tokenCount; ++t) {
					if (response.tokenIs(t) == OPAL_TOKEN::ENDLIST) {
						break;
					}
					char buf[4];
					sprintf(buf, " %xh", response.getUint32(t));
					resets.append(buf);
				}
				break;
			case 20:
				ns = to_string(response.getUint64(++t));
				break;
			case 21:
				global = response.getUint32(++t) ? "Y" : "N";
				break;
			default:
				for (++t; t < tokenCount; ++t) {
					if (response.tokenIs(t) == OPAL_TOKEN::ENDNAME) {
						--t;
						break;
					}
				}
				break;
			}
		}

		LOG(I) << "LR" << i << " Begin " << rangeStart << " for " << rangeLength;
		LOG(I) << "    RLKEna = " << rle << "  WLKEna = " << wle <<
			          "  RLocked = " << rl << "  WLocked = " << wl << resets;
        LOG(I) << "    NamespaceID = " << ns << "  Global = " << global;
	}

	delete session;
	LOG(D1) << "Exiting DtaDevOpal:listLockingRanges()";
	return 0;
}

uint8_t DtaDevOpal::setupLockingRange(const uint8_t lockingrange, const uint64_t start,
                                      const uint64_t length, const char* authority, const char* password)
{
	uint8_t lastRC;
	LOG(D1) << "Entering DtaDevOpal:setupLockingRange()";
	if (lockingrange < 1) {
		LOG(E) << "global locking range cannot be changed";
		return DTAERROR_UNSUPORTED_LOCKING_RANGE;
	}
	vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}
	LR[6] = 0x03;
	LR[8] = lockingrange;

    vector<uint8_t> authorityUID;
	if ((lastRC = getAuth4User(OPAL_UID::OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}
	DtaCommand *set = new DtaCommand();
	if (NULL == set) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	set->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::SET);
	set->changeInvokingUid(LR);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::VALUES);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::RANGESTART);
	set->addToken(start);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::RANGELENGTH);
	set->addToken(length);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::READLOCKENABLED);
	set->addToken(OPAL_TOKEN::OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::WRITELOCKENABLED);
	set->addToken(OPAL_TOKEN::OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::READLOCKED);
	set->addToken(OPAL_TOKEN::OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::WRITELOCKED);
	set->addToken(OPAL_TOKEN::OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->complete();
	if ((lastRC = session->sendCommand(set, response)) != 0) {
		LOG(E) << "setupLockingRange Failed ";
		delete set;
		delete session;
		return lastRC;
	}
	delete set;
	delete session;
	if ((lastRC = rekeyLockingRange(lockingrange, authority, password)) != 0) {
		LOG(E) << "setupLockingRange Unable to reKey Locking range -- Possible security issue ";
		return lastRC;
	}
	LOG(I) << "LockingRange" << (uint16_t)lockingrange << " starting block " << start <<
		" for " << length << " blocks configured as unlocked range";
	LOG(D1) << "Exiting DtaDevOpal:setupLockingRange()";
	return 0;
}

uint8_t DtaDevOpal::setupLockingRange_SUM(const uint8_t lockingrange, const uint64_t start,
                                          const uint64_t length, const char* password)
{
	uint8_t lastRC;
	LOG(D1) << "Entering DtaDevOpal:setupLockingRange_SUM()";
	if (lockingrange < 1) {
		LOG(E) << "global locking range cannot be changed";
		return DTAERROR_UNSUPORTED_LOCKING_RANGE;
	}
	vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}
	LR[6] = 0x03;
	LR[8] = lockingrange;
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	vector<uint8_t> auth;
	auth.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 7; i++) {
		auth.push_back(OPALUID[OPAL_UID::OPAL_USER1_UID][i]);
	}
	auth.push_back(lockingrange+1);
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, auth)) != 0) {
		LOG(E) << "Error starting session. Did you provide the correct user password? (GlobalRange = User1; Range1 = User2, etc.)";
		delete session;
		return lastRC;
	}
	DtaCommand *set = new DtaCommand();
	if (NULL == set) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	set->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::SET);
	set->changeInvokingUid(LR);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::VALUES);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::RANGESTART);
	set->addToken(start);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::RANGELENGTH);
	set->addToken(length);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::READLOCKENABLED);
	set->addToken(OPAL_TOKEN::OPAL_TRUE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::WRITELOCKENABLED);
	set->addToken(OPAL_TOKEN::OPAL_TRUE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::READLOCKED);
	set->addToken(OPAL_TOKEN::OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::WRITELOCKED);
	set->addToken(OPAL_TOKEN::OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->complete();
	if ((lastRC = session->sendCommand(set, response)) != 0) {
		LOG(E) << "setupLockingRange Failed ";
		delete set;
		delete session;
		return lastRC;
	}
	delete set;
	delete session;
	if ((lastRC = rekeyLockingRange_SUM(LR, auth, password)) != 0) {
		LOG(E) << "setupLockingRange Unable to reKey Locking range -- Possible security issue ";
		return lastRC;
	}
	LOG(I) << "LockingRange" << (uint16_t)lockingrange << " starting block " << start <<
		" for " << length << " blocks configured as LOCKED range";
	LOG(D1) << "Exiting DtaDevOpal:setupLockingRange_SUM()";
	return 0;
}

uint8_t DtaDevOpal::configureLockingRange(const uint8_t lockingrange, const uint8_t enabled,
                                          const char* authority, const char* password)
{
	uint8_t lastRC;
	LOG(D1) << "Entering DtaDevOpal::configureLockingRange()";
	vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}
	if (lockingrange != 0) {
		LR[6] = 0x03;
		LR[8] = lockingrange;
	}

    vector<uint8_t> authorityUID;
	if ((lastRC = getAuth4User(OPAL_UID::OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}
	DtaCommand *set = new DtaCommand();
	if (NULL == set) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	set->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::SET);
	set->changeInvokingUid(LR);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::VALUES);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::READLOCKENABLED);
	set->addToken((enabled & DTA_READLOCKINGENABLED) ? OPAL_TRUE : OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::WRITELOCKENABLED);
	set->addToken((enabled & DTA_WRITELOCKINGENABLED) ? OPAL_TRUE : OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->complete();
	if ((lastRC = session->sendCommand(set, response)) != 0) {
		LOG(E) << "configureLockingRange Failed ";
		delete set;
		delete session;
		return lastRC;
	}
	delete set;
	delete session;
	LOG(I) << "LockingRange" << (uint16_t) lockingrange
		<< (enabled ? " enabled " : " disabled ")
		<< ((enabled & DTA_READLOCKINGENABLED) ? "ReadLocking" : "")
		<< ((enabled == (DTA_WRITELOCKINGENABLED | DTA_READLOCKINGENABLED)) ? "," : "")
		<< ((enabled & DTA_WRITELOCKINGENABLED) ? "WriteLocking" : "");
	LOG(D1) << "Exiting DtaDevOpal::configureLockingRange()";
	return 0;
}

uint8_t DtaDevOpal::configureLockingRange_SUM(const uint8_t lockingrange,
                                              const OPAL_LOCKINGSTATE enabled,
                                              const char* password)
{
	uint8_t lastRC;
	LOG(D1) << "Entering DtaDevOpal::configureLockingRange_SUM()";

    uint8_t writeLockEnable = 0;
    uint8_t readLockEnable = 0;
    switch (enabled) {
    case OPAL_LOCKINGSTATE::DISABLED:
        break;
    case OPAL_LOCKINGSTATE::READONLY:
        readLockEnable = 1;
        break;
    case OPAL_LOCKINGSTATE::LOCKED:
        writeLockEnable = 1;
        break;
    case OPAL_LOCKINGSTATE::READWRITE:
        readLockEnable = 1;
        writeLockEnable = 1;
        break;
    default:
        break;
    }

    vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}
	if (lockingrange != 0) {
		LR[6] = 0x03;
		LR[8] = lockingrange;
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}

	vector<uint8_t> auth;
	auth.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 7; i++) {
		auth.push_back(OPALUID[OPAL_UID::OPAL_USER1_UID][i]);
	}
	auth.push_back(lockingrange+1);
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, auth)) != 0) {
		LOG(E) << "Error starting session. Did you provide the correct user password? (GlobalRange = User1; Range1 = User2, etc.)";
		delete session;
		return lastRC;
	}
	DtaCommand *set = new DtaCommand();
	if (NULL == set) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	set->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::SET);
	set->changeInvokingUid(LR);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::VALUES);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::READLOCKENABLED);
	set->addToken(readLockEnable ? OPAL_TRUE : OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::WRITELOCKENABLED);
	set->addToken(writeLockEnable ? OPAL_TRUE : OPAL_FALSE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->complete();
	if ((lastRC = session->sendCommand(set, response)) != 0) {
		LOG(E) << "configureLockingRange Failed ";
		delete set;
		delete session;
		return lastRC;
	}
	delete set;
	delete session;
	LOG(I) << "LockingRange" << (uint16_t) lockingrange
		<< ", ReadLocking " << (readLockEnable ? "enabled" : "disabled")
		<< ", WriteLocking " << (writeLockEnable ? "enabled" : "disabled");
	LOG(D1) << "Exiting DtaDevOpal::configureLockingRange()";
	return 0;
}

uint8_t DtaDevOpal::rekeyLockingRange(const uint8_t lockingrange, const char* authority, const char* password)
{
	LOG(D1) << "Entering DtaDevOpal::rekeyLockingRange()";
	uint8_t lastRC;
	vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}
	if (lockingrange != 0) {
		LR[6] = 0x03;
		LR[8] = lockingrange;
	}

    vector<uint8_t> authorityUID;
	if ((lastRC = getAuth4User(OPAL_UID::OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}
	if ((lastRC = getTable(LR, OPAL_TOKEN::ACTIVEKEY, OPAL_TOKEN::ACTIVEKEY)) != 0) {
		delete session;
		return lastRC;
	}
	DtaCommand *rekey = new DtaCommand();
	if (NULL == rekey) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	rekey->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::GENKEY);
	rekey->changeInvokingUid(response.getRawToken(4));
	rekey->addToken(OPAL_TOKEN::STARTLIST);
	rekey->addToken(OPAL_TOKEN::ENDLIST);
	rekey->complete();
	if ((lastRC = session->sendCommand(rekey, response)) != 0) {
		LOG(E) << "rekeyLockingRange Failed ";
		delete rekey;
		delete session;
		return lastRC;
	}
	delete rekey;
	delete session;
	LOG(I) << "LockingRange" << (uint16_t)lockingrange << " reKeyed ";
	LOG(D1) << "Exiting DtaDevOpal::rekeyLockingRange()";
	return 0;
}

uint8_t DtaDevOpal::rekeyLockingRange_SUM(const std::vector<uint8_t>& LR,
                                          const std::vector<uint8_t>& UID,
                                          const char* password)
{
	LOG(D1) << "Entering DtaDevOpal::rekeyLockingRange_SUM()";
	uint8_t lastRC;

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, UID)) != 0) {
		delete session;
		return lastRC;
	}
	if ((lastRC = getTable(LR, OPAL_TOKEN::ACTIVEKEY, OPAL_TOKEN::ACTIVEKEY)) != 0) {
		delete session;
		return lastRC;
	}
	DtaCommand *rekey = new DtaCommand();
	if (NULL == rekey) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	rekey->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::GENKEY);
	rekey->changeInvokingUid(response.getRawToken(4));
	rekey->addToken(OPAL_TOKEN::STARTLIST);
	rekey->addToken(OPAL_TOKEN::ENDLIST);
	rekey->complete();
	if ((lastRC = session->sendCommand(rekey, response)) != 0) {
		LOG(E) << "rekeyLockingRange_SUM Failed ";
		delete rekey;
		delete session;
		return lastRC;
	}
	delete rekey;
	delete session;
	LOG(I) << "LockingRange reKeyed ";
	LOG(D1) << "Exiting DtaDevOpal::rekeyLockingRange_SUM()";
	return 0;
}

uint8_t DtaDevOpal::assign(const char* authority, const char* password, const uint32_t ns,
                           const uint64_t start, const uint64_t length, const uint32_t sum)
{
	uint8_t lastRC;
	LOG(D1) << "Entering DtaDevOpal::assign(), nsid: " << ns << ", start: " << start <<
               ", length: " << length << ", sum: " << sum;

    std::vector<uint8_t> nspace;
    nspace.push_back(BYTESTRING4);
    nspace.push_back((ns >> 24) & 0xff);
    nspace.push_back((ns >> 16) & 0xff);
    nspace.push_back((ns >> 8) & 0xff);
    nspace.push_back((ns >> 0) & 0xff);

    vector<uint8_t> authorityUID;
	if ((lastRC = getAuth4User(OPAL_UID::OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}
	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	cmd->reset(OPAL_UID::OPAL_LOCKING_TABLE, OPAL_METHOD::ASSIGN);
	cmd->addToken(OPAL_TOKEN::STARTLIST);
		cmd->addToken(nspace);					    // first required argument, Namespace
		cmd->addToken(OPAL_TOKEN::STARTNAME);
			cmd->addToken((uint64_t)0);
			cmd->addToken(start);					// first optional argument, RangeStart
		cmd->addToken(OPAL_TOKEN::ENDNAME);
		cmd->addToken(OPAL_TOKEN::STARTNAME);
			cmd->addToken((uint64_t)1);
			cmd->addToken(length);					// second optional argument, Rangelength
		cmd->addToken(OPAL_TOKEN::ENDNAME);
	if (sum) {
		cmd->addToken(OPAL_TOKEN::STARTNAME);
			cmd->addToken((uint64_t)2);
			cmd->addToken(OPAL_TRUE);				// third optional argument, AssignToSUMRange
		cmd->addToken(OPAL_TOKEN::ENDNAME);
		}
	cmd->addToken(OPAL_TOKEN::ENDLIST);
	cmd->complete();
	if ((lastRC = session->sendCommand(cmd, response)) != 0) {
		LOG(E) << "assign call Failed ";
		delete cmd;
		delete session;
		return lastRC;
	}
	delete cmd;

	// Assign call returns 2 values, the UID of the Locking table row that was
	// configured for the new locking range, and an indicatgor if the range is
	// global to the namespace.
	if (response.getTokenCount() < 5)
	{
		LOG(E) << "assign command did not return enough data, token count is " <<
			response.getTokenCount();
		delete session;
		return DTAERROR_NO_LOCKING_INFO;
	}

	uint8_t uid[8];
	char    uidStr[20];
	response.getBytes(1, uid);
	uint32_t lr = (uid[6] << 8) + uid[7];
	printBytes(uid, 8, uidStr);

	LOG(I) << "Locking Range UID: " << uidStr << " (LR" << lr << ") assigned to namespace "
		<< ns << ", global: " << (response.getUint8(2) ? "T" : "F");

	delete session;
	return 0;
}

uint8_t DtaDevOpal::deassign(const char* authority, const char* password,
                             const uint8_t lockingrange, const bool keep)
{
	uint8_t lastRC;
	LOG(D1) << "Entering DtaDevOpal::deassign()";

	std::vector<uint8_t> uid = {OPAL_SHORT_ATOM::BYTESTRING8, 0x00, 0x00, 0x08, 0x02, 0x00, 0x03, 0x00};
	uid.push_back(lockingrange);

    vector<uint8_t> authorityUID;
	if ((lastRC = getAuth4User(OPAL_UID::OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}
	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	cmd->reset(OPAL_UID::OPAL_LOCKING_TABLE, OPAL_METHOD::DEASSIGN);
	cmd->addToken(OPAL_TOKEN::STARTLIST);
		cmd->addToken(uid);							// first required argument, range UID
	if (keep) {
		cmd->addToken(OPAL_TOKEN::STARTNAME);
			cmd->addToken((uint64_t)0);				// first optional argument
			cmd->addToken(OPAL_TOKEN::OPAL_TRUE);	// KeepNamespaceGlobalRnageKey
		cmd->addToken(OPAL_TOKEN::ENDNAME);
	}
	cmd->addToken(OPAL_TOKEN::ENDLIST);
	cmd->complete();
	if ((lastRC = session->sendCommand(cmd, response)) != 0) {
		LOG(E) << "deassign call Failed ";
		delete cmd;
		delete session;
		return lastRC;
	}

	std::string uidStr;
	uid.erase(uid.begin());
	printUID(uid, uidStr);

	LOG(I) << "Locking Range UID: " << uidStr << " (LR" << (int)lockingrange << ") deassigned";

	delete cmd;
	delete session;
	return 0;
}

uint8_t DtaDevOpal::setBandsEnabled(const int16_t lockingrange, const char* password)
{
	if (password == NULL) { LOG(D4) << "Password is NULL"; } // unreferenced formal paramater
	LOG(D1) << "Entering DtaDevOpal::setBandsEnabled()" << lockingrange << " " << dev;
	LOG(I) << "setBandsEnabled is not implemented.  It is not part of the Opal SSC ";
	LOG(D1) << "Exiting DtaDevOpal::setBandsEnabled()";
	return 0;
}

uint8_t DtaDevOpal::revertSP(const char* sp, const char* authority, const char* password, const uint8_t keep)
{
	LOG(D1) << "Entering DtaDevOpal::revertSP(), sp = " << sp << ", keep = " << (uint16_t) keep;
	uint8_t lastRC;

    OPAL_UID spUID = (sp[0] == 'A' || sp[0] == 'a') ? OPAL_UID::OPAL_ADMINSP_UID : OPAL_UID::OPAL_LOCKINGSP_UID;

    vector<uint8_t> authorityUID;
	if ((lastRC = getAuth4User(spUID, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}

	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Create session object failed";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Create session object failed";
		delete cmd;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(spUID, password, authorityUID)) != 0) {
		delete cmd;
		delete session;
        LOG(E) << "Start session failed";
		return lastRC;
	}

	cmd->reset(OPAL_UID::OPAL_THISSP_UID, OPAL_METHOD::REVERTSP);
	cmd->addToken(OPAL_TOKEN::STARTLIST);
	if (keep) {
        std::vector<uint8_t> keepGlobalLocking = {0x83, 0x06, 0x00, 0x00};
		cmd->addToken(OPAL_TOKEN::STARTNAME);
		cmd->addToken(keepGlobalLocking);
		cmd->addToken(OPAL_TOKEN::OPAL_TRUE);
		cmd->addToken(OPAL_TOKEN::ENDNAME);
	}
	cmd->addToken(OPAL_TOKEN::ENDLIST);
	cmd->complete();
	if ((lastRC = session->sendCommand(cmd, response)) != 0) {
        LOG(E) << "Command failed";
		delete cmd;
		delete session;
		return lastRC;
	}

	// empty list returned so rely on method status
	LOG(I) << "RevertSP complete";
	session->expectAbort();
	delete cmd;
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::revertSP()";
	return 0;
}

uint8_t DtaDevOpal::eraseLockingRange(const uint8_t lockingrange, const char* password)
{
	LOG(D1) << "Entering DtaDevOpal::eraseLockingRange()" << lockingrange << " " << dev;
	if (password == NULL) { LOG(D4) << "Referencing formal parameters " << lockingrange; }
	LOG(I) << "eraseLockingRange is not implemented.  It is not part of the Opal SSC ";
	LOG(D1) << "Exiting DtaDevOpal::eraseLockingRange()";
	return 0;
}

uint8_t DtaDevOpal::getAuth4User(const OPAL_UID sp, const char* userid, const uint8_t uidorcpin,
                                 std::vector<uint8_t>& userData) const
{
	LOG(D1) << "Entering DtaDevOpal::getAuth4User()";
	userData.clear();
	userData.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	userData.push_back(0x00);
	userData.push_back(0x00);
	userData.push_back(0x00);
	if ((0 != uidorcpin) && (10 != uidorcpin)) {
		LOG(E) << "Invalid Userid data requested" << (uint16_t)uidorcpin;
		return DTAERROR_INVALID_PARAMETER;
	}
	if(uidorcpin)
		userData.push_back(0x0b);
	else
		userData.push_back(0x09);

    if (!memcmp("Anonymous", userid, 9) || !memcmp("anonymous", userid, 9)) {
        userData.clear();
    }
    else if (!memcmp("Anybody", userid, 7) || !memcmp("anybody", userid, 7)) {
        userData.push_back(0x00);
        userData.push_back(0x00);
        userData.push_back(0x00);
        userData.push_back(0x01);
    }
    else if (!memcmp("Admins", userid, 6)) {
        userData.push_back(0x00);
        userData.push_back(0x00);
        userData.push_back(0x00);
        userData.push_back(0x02);
    }

    else if (sp == OPAL_UID::OPAL_LOCKINGSP_UID) {
        if (!memcmp("User", userid, 4)) {
    		userData.push_back(0x00);
    		userData.push_back(0x03);
    		userData.push_back(0x00);
    		userData.push_back(atoi(&userid[4]) &0xff );
        }
        else if (!memcmp("Admin", userid, 5)) {
            userData.push_back(0x00);
            userData.push_back(0x01);
            userData.push_back(0x00);
            userData.push_back(atoi(&userid[5]) & 0xff );
        }
    	else {
            LOG(E) << "Invalid Userid " << userid;
            userData.clear();
            return DTAERROR_INVALID_PARAMETER;
    	}
    }
    else {
        if (!memcmp("SID", userid, 3)) {
    		userData.push_back(0x00);
    		userData.push_back(0x00);
    		userData.push_back(0x00);
    		userData.push_back(uidorcpin ? 0x01 : 0x06);
    	}
    	else if (!memcmp("Admin", userid, 5)) {
            userData.push_back(0x00);
            userData.push_back(0x00);
            userData.push_back(0x02);
            userData.push_back(atoi(&userid[5]) & 0xff);
        }
        else if (!memcmp("PSID", userid, 4)) {
            userData.push_back(0x00);
            userData.push_back(0x01);
            userData.push_back(0xFF);
            userData.push_back(0x01);
        }
    	else {
            LOG(E) << "Invalid Userid " << userid;
            userData.clear();
            return DTAERROR_INVALID_PARAMETER;
    	}
    }
	LOG(D1) << "Exiting DtaDevOpal::getAuth4User()";
	return 0;
}

uint8_t DtaDevOpal::setPassword(const char* sp, const char* authority, const char* password,
                                const char* userid, const char* newpassword)
{
	LOG(D1) << "Entering DtaDevOpal::setPassword" ;
	uint8_t lastRC;
	std::vector<uint8_t> userCPIN, hash, authorityUID;

    OPAL_UID spuid = (sp[0] == 'A') ? OPAL_UID::OPAL_ADMINSP_UID : OPAL_UID::OPAL_LOCKINGSP_UID;

	if ((lastRC = getAuth4User(spuid, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}
	if ((lastRC = getAuth4User(spuid, userid, 10, userCPIN)) != 0) {
		LOG(E) << "Unable to find user " << userid << " in Authority Table";
		return lastRC;
	}

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(spuid, password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}

	DtaHashPwd(hash, newpassword, this);
	if ((lastRC = setTable(userCPIN, OPAL_TOKEN::PIN, hash)) != 0) {
		LOG(E) << "Unable to set user " << userid << " new password ";
		delete session;
		return lastRC;
	}
	LOG(I) << userid << " password changed";
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::setPassword()";
	return 0;
}

uint8_t DtaDevOpal::setNewPassword_SUM(const char* password, const char* userid,
                                       const char* newpassword)
{
	LOG(D1) << "Entering DtaDevOpal::setNewPassword_SUM";
	uint8_t lastRC;
	std::vector<uint8_t> userCPIN, hash;
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	vector<uint8_t> auth;
	if (!memcmp("Admin", userid, 5))
	{

		auth.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
		for (int i = 0; i < 7; i++) {
			auth.push_back(OPALUID[OPAL_UID::OPAL_ADMIN1_UID][i]);
		}
		auth.push_back((uint8_t)atoi(&userid[5]));
	}
	else if (!memcmp("User", userid, 4))
	{
		auth.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
		for (int i = 0; i < 7; i++) {
			auth.push_back(OPALUID[OPAL_UID::OPAL_USER1_UID][i]);
		}
		auth.push_back((uint8_t)atoi(&userid[4]));
	}
	else
	{
		LOG(E) << "Invalid userid \"" << userid << "\"specified for setNewPassword_SUM";
		delete session;
		return DTAERROR_INVALID_PARAMETER;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, auth)) != 0) {
		delete session;
		return lastRC;
	}
	if ((lastRC = getAuth4User(OPAL_UID::OPAL_LOCKINGSP_UID, userid, 10, userCPIN)) != 0) {
		LOG(E) << "Unable to find user " << userid << " in Authority Table";
		delete session;
		return lastRC;
	}
	DtaHashPwd(hash, newpassword, this);
	if ((lastRC = setTable(userCPIN, OPAL_TOKEN::PIN, hash)) != 0) {
		LOG(E) << "Unable to set user " << userid << " new password ";
		delete session;
		return lastRC;
	}
	LOG(I) << userid << " password changed";
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::setNewPassword_SUM()";
	return 0;
}

uint8_t DtaDevOpal::setMBREnable(const uint8_t mbrstate, const char* Admin1Password)
{
	LOG(D1) << "Entering DtaDevOpal::setMBREnable";
	uint8_t lastRC = 0;

	if (mbrstate) {
		// Setting MBR Enable.  Set MBR Done in the same command.
		session = new DtaSession(this);
		if (NULL == session) {
			LOG(E) << "Unable to create session object";
			return DTAERROR_OBJECT_CREATE_FAILED;
		}
		if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, Admin1Password, OPAL_UID::OPAL_ADMIN1_UID)) != 0) {
			delete session;
			return lastRC;
		}

		DtaCommand *cmd = new DtaCommand();
		if (NULL == cmd) {
			LOG(E) << "Unable to create command object";
			delete session;
			return DTAERROR_OBJECT_CREATE_FAILED;
		}

		cmd->reset(OPAL_UID::OPAL_MBRCONTROL, OPAL_METHOD::SET);
		cmd->addToken(OPAL_TOKEN::STARTLIST);
			cmd->addToken(OPAL_TOKEN::STARTNAME);
			cmd->addToken(OPAL_TOKEN::VALUES);
			cmd->addToken(OPAL_TOKEN::STARTLIST);
				cmd->addToken(OPAL_TOKEN::STARTNAME);
				cmd->addToken(OPAL_TOKEN::MBRENABLE);
				cmd->addToken(OPAL_TOKEN::OPAL_TRUE);
				cmd->addToken(OPAL_TOKEN::ENDNAME);
				cmd->addToken(OPAL_TOKEN::STARTNAME);
				cmd->addToken(OPAL_TOKEN::MBRDONE);
				cmd->addToken(OPAL_TOKEN::OPAL_TRUE);
				cmd->addToken(OPAL_TOKEN::ENDNAME);
			cmd->addToken(OPAL_TOKEN::ENDLIST);
			cmd->addToken(OPAL_TOKEN::ENDNAME);
		cmd->addToken(OPAL_TOKEN::ENDLIST);
		cmd->complete();

		if ((lastRC = session->sendCommand(cmd, response)) != 0) {
			LOG(E) << "Unable to set setMBREnable on ";
		}
		else {
			LOG(I) << "MBREnable set on ";
		}
		delete cmd;
		delete session;
	}
	else {
		// Clearing MBR Enable
		if ((lastRC = setLockingSPvalue(OPAL_UID::OPAL_MBRCONTROL, OPAL_TOKEN::MBRENABLE,
			OPAL_TOKEN::OPAL_FALSE, Admin1Password, NULL)) != 0) {
			LOG(E) << "Unable to set setMBREnable off ";
		}
		else {
			LOG(I) << "MBREnable set off ";
		}
	}
	LOG(D1) << "Exiting DtaDevOpal::setMBREnable";
	return 0;
}

uint8_t DtaDevOpal::setMBRDone(const uint8_t mbrstate, const char* Admin1Password)
{
	LOG(D1) << "Entering DtaDevOpal::setMBRDone";
	uint8_t lastRC;
	if (mbrstate) {
		if ((lastRC = setLockingSPvalue(OPAL_UID::OPAL_MBRCONTROL, OPAL_TOKEN::MBRDONE,
			OPAL_TOKEN::OPAL_TRUE, Admin1Password, NULL)) != 0) {
			LOG(E) << "Unable to set setMBRDone on";
			return lastRC;
		}
		else {
			LOG(I) << "MBRDone set on ";
		}
	}
	else {
		if ((lastRC = setLockingSPvalue(OPAL_UID::OPAL_MBRCONTROL, OPAL_TOKEN::MBRDONE,
			OPAL_TOKEN::OPAL_FALSE, Admin1Password, NULL)) != 0) {
			LOG(E) << "Unable to set setMBRDone off";
			return lastRC;
		}
		else {
			LOG(I) << "MBRDone set off ";
		}
	}
	LOG(D1) << "Exiting DtaDevOpal::setMBRDone";
	return lastRC;
}

uint8_t DtaDevOpal::setLockingRange(const uint8_t lockingrange, const uint8_t lockingstate,
                                    const char* authority, const char* Admin1Password)
{
	uint8_t lastRC;
	uint8_t archiveuser = 0;
	OPAL_TOKEN readlocked  = OPAL_TOKEN::EMPTYATOM;
    OPAL_TOKEN writelocked = OPAL_TOKEN::EMPTYATOM;
    const char *msg;
    std::vector<uint8_t> lockOnReset;
    std::vector<uint8_t> authorityUID;

	if ((lastRC = getAuth4User(OPAL_UID::OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}

	LOG(D1) << "Entering DtaDevOpal::setLockingRange";
	switch (lockingstate) {
	case OPAL_LOCKINGSTATE::READWRITE:
		readlocked = writelocked = OPAL_TOKEN::OPAL_FALSE;
		msg = "RW";
		break;
	case OPAL_LOCKINGSTATE::ARCHIVEUNLOCKED:
		archiveuser = 1;
	case OPAL_LOCKINGSTATE::READONLY:
		readlocked = OPAL_TOKEN::OPAL_FALSE;
		writelocked = OPAL_TOKEN::OPAL_TRUE;
		msg = "RO";
		break;
	case OPAL_LOCKINGSTATE::WRITEONLY:
		readlocked = OPAL_TOKEN::OPAL_TRUE;
		writelocked = OPAL_TOKEN::OPAL_FALSE;
		msg = "WO";
		break;
	case OPAL_LOCKINGSTATE::ARCHIVELOCKED:
		archiveuser = 1;
	case OPAL_LOCKINGSTATE::LOCKED:
		readlocked = writelocked = OPAL_TOKEN::OPAL_TRUE;
		msg = "LK";
		break;
    case OPAL_LOCKINGSTATE::ENABLERESET:
        // This only works because the 2 values we use fit in a tiny token.
        lockOnReset.push_back(OPAL_TOKEN::POWER_CYCLE);
        lockOnReset.push_back(OPAL_TOKEN::PROGRAMMATIC);
        msg = "+R";
        break;
    case OPAL_LOCKINGSTATE::DISABLERESET:
        // This only works because the value we use fits in a tiny token.
        lockOnReset.push_back(OPAL_TOKEN::POWER_CYCLE);
        msg = "-R";
        break;
	default:
		LOG(E) << "Invalid locking state for setLockingRange";
		return DTAERROR_INVALID_PARAMETER;
	}
	vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}
	if (lockingrange != 0) {
		LR[6] = 0x03;
		LR[8] = lockingrange;
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, Admin1Password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}
	DtaCommand *set = new DtaCommand();
	if (NULL == set) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	set->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::SET);
	set->changeInvokingUid(LR);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::VALUES);
	set->addToken(OPAL_TOKEN::STARTLIST);
    if (readlocked != OPAL_TOKEN::EMPTYATOM) {
        set->addToken(OPAL_TOKEN::STARTNAME);
        set->addToken(OPAL_TOKEN::READLOCKED);
        set->addToken(readlocked);
        set->addToken(OPAL_TOKEN::ENDNAME);
    }
	if (!archiveuser && (writelocked != OPAL_TOKEN::EMPTYATOM)) {
		set->addToken(OPAL_TOKEN::STARTNAME);
		set->addToken(OPAL_TOKEN::WRITELOCKED);
		set->addToken(writelocked);
		set->addToken(OPAL_TOKEN::ENDNAME);
	}
    if (lockOnReset.size() != 0) {
		set->addToken(OPAL_TOKEN::STARTNAME);
        set->addToken(OPAL_TOKEN::LOCKONRESET);
        set->addToken(OPAL_TOKEN::STARTLIST);
		set->addToken(lockOnReset);
        set->addToken(OPAL_TOKEN::ENDLIST);
		set->addToken(OPAL_TOKEN::ENDNAME);
    }
    set->addToken(OPAL_TOKEN::ENDLIST);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->complete();
	if ((lastRC = session->sendCommand(set, response)) != 0) {
		LOG(E) << "setLockingRange Failed ";
		delete set;
		delete session;
		return lastRC;
	}
	delete set;
	delete session;
	LOG(I) << "LockingRange" << (uint16_t)lockingrange << " set to " << msg;
	LOG(D1) << "Exiting DtaDevOpal::setLockingRange";
	return 0;
}

uint8_t DtaDevOpal::setLockingRange_SUM(const uint8_t lockingrange, const uint8_t lockingstate,
                                        const char* password)
{
	uint8_t lastRC;
	OPAL_TOKEN readlocked, writelocked;
	const char *msg;

	LOG(D1) << "Entering DtaDevOpal::setLockingRange_SUM";
	switch (lockingstate) {
	case OPAL_LOCKINGSTATE::READWRITE:
		readlocked = writelocked = OPAL_TOKEN::OPAL_FALSE;
		msg = "RW";
		break;
	case OPAL_LOCKINGSTATE::READONLY:
		readlocked = OPAL_TOKEN::OPAL_FALSE;
		writelocked = OPAL_TOKEN::OPAL_TRUE;
		msg = "RO";
		break;
	case OPAL_LOCKINGSTATE::WRITEONLY:
		readlocked = OPAL_TOKEN::OPAL_TRUE;
		writelocked = OPAL_TOKEN::OPAL_FALSE;
		msg = "WO";
		break;
	case OPAL_LOCKINGSTATE::LOCKED:
		readlocked = writelocked = OPAL_TOKEN::OPAL_TRUE;
		msg = "LK";
		break;
	default:
		LOG(E) << "Invalid locking state for setLockingRange";
		return DTAERROR_INVALID_PARAMETER;
	}
	vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}
	if (lockingrange != 0) {
		LR[6] = 0x03;
		LR[8] = lockingrange;
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	vector<uint8_t> auth;
	auth.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 7; i++) {
		auth.push_back(OPALUID[OPAL_UID::OPAL_USER1_UID][i]);
	}
	auth.push_back(lockingrange+1);
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, auth)) != 0) {
		LOG(E) << "Error starting session. Did you provide the correct user password? (GlobalRange = User1; Range1 = User2, etc.)";
		delete session;
		return lastRC;
	}

	DtaCommand *set = new DtaCommand();
	if (NULL == set) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	set->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::SET);
	set->changeInvokingUid(LR);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::VALUES);
	set->addToken(OPAL_TOKEN::STARTLIST);

	//enable locking on the range to enforce lock state
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::READLOCKENABLED);
	set->addToken(OPAL_TOKEN::OPAL_TRUE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::WRITELOCKENABLED);
	set->addToken(OPAL_TOKEN::OPAL_TRUE);
	set->addToken(OPAL_TOKEN::ENDNAME);
	//set read/write locked
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::READLOCKED);
	set->addToken(readlocked);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::WRITELOCKED);
	set->addToken(writelocked);
	set->addToken(OPAL_TOKEN::ENDNAME);

	set->addToken(OPAL_TOKEN::ENDLIST);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->complete();
	if ((lastRC = session->sendCommand(set, response)) != 0) {
		LOG(E) << "setLockingRange Failed ";
		delete set;
		delete session;
		return lastRC;
	}
	delete set;
	delete session;
	LOG(I) << "LockingRange" << (uint16_t)lockingrange << " set to " << msg;
	LOG(D1) << "Exiting DtaDevOpal::setLockingRange_SUM";
	return 0;
}

uint8_t DtaDevOpal::setLockingSPvalue(const OPAL_UID table_uid, const OPAL_TOKEN name,
                                      const OPAL_TOKEN value, const char* password, const char* msg)
{
	LOG(D1) << "Entering DtaDevOpal::setLockingSPvalue";
	uint8_t lastRC;
	vector<uint8_t> table;
	table. push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		table.push_back(OPALUID[table_uid][i]);
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, OPAL_UID::OPAL_ADMIN1_UID)) != 0) {
		delete session;
		return lastRC;
	}
	if ((lastRC = setTable(table, name, value)) != 0) {
		LOG(E) << "Unable to update table";
		delete session;
		return lastRC;
	}
	if (NULL != msg) {
		LOG(I) << msg;
	}

	delete session;
	LOG(D1) << "Exiting DtaDevOpal::setLockingSPvalue()";
	return 0;
}

uint8_t DtaDevOpal::enableUser(const char* sp, const char* authority, const char* password, const char* userid,
                               const OPAL_TOKEN status)
{
	LOG(D1) << "Entering DtaDevOpal::enableUser";
	uint8_t lastRC;
	vector<uint8_t> userUID;
    vector<uint8_t> authorityUID;

    OPAL_UID spuid = (sp[0] == 'A') ? OPAL_UID::OPAL_ADMINSP_UID : OPAL_UID::OPAL_LOCKINGSP_UID;

	if ((lastRC = getAuth4User(spuid, authority, 0, authorityUID)) != 0) {
		LOG(E) << "Invalid Authority provided " << authority;
		return lastRC;
	}

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}

	if ((lastRC = session->start(spuid, password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}
	if ((lastRC = getAuth4User(spuid, userid, 0, userUID)) != 0) {
		LOG(E) << "Unable to find user " << userid << " in Authority Table";
		delete session;
		return lastRC;
	}
	if ((lastRC = setTable(userUID, (OPAL_TOKEN)0x05, status)) != 0) {
		LOG(E) << "Unable to enable user " << userid;
		delete session;
		return lastRC;
	}
	LOG(I) << userid << " has been enabled ";
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::enableUser()";
	return 0;
}

uint8_t DtaDevOpal::revertTPer(const char* authority, const char* password, const uint8_t AdminSP)
{
	LOG(D1) << "Entering DtaDevOpal::revertTPer() " << AdminSP;

	uint8_t lastRC;
    std::vector<uint8_t> authorityUID;

    if ((lastRC = getAuth4User(OPAL_UID::OPAL_ADMINSP_UID, authority, 0, authorityUID)) != 0) {
        LOG(E) << "Invalid Authority provided " << authority;
        return lastRC;
    }

	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		delete cmd;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}

	if (!strcmp(authority, "PSID")) {
		session->dontHashPwd(); // PSID pwd should be passed as entered
	}

	if ((lastRC = session->start(OPAL_UID::OPAL_ADMINSP_UID, password, authorityUID)) != 0) {
		delete cmd;
		delete session;
		return lastRC;
	}
	cmd->reset(OPAL_UID::OPAL_ADMINSP_UID, OPAL_METHOD::REVERT);
	cmd->addToken(OPAL_TOKEN::STARTLIST);
	cmd->addToken(OPAL_TOKEN::ENDLIST);
	cmd->complete();
	if ((lastRC = session->sendCommand(cmd, response)) != 0) {
		delete cmd;
		delete session;
		return lastRC;
	}
	LOG(I) << "revertTper completed successfully";
	session->expectAbort();
	delete cmd;
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::revertTPer()";
	return 0;
}

uint8_t DtaDevOpal::getTableWriteGranularity(std::vector<uint8_t>& tableRowUID, uint32_t* gran)
{
    LOG(D1) << "Entering DtaDevOpal::getTableWriteGranularity";

    // Session to the LockingSP should already be open
    uint8_t lastRC = getTable(tableRowUID, 0x0d, 0x0e);
    if (lastRC == 0) {
        if ((response.getTokenCount() > 6) && (response.getUint32(3) == 0x0D)) {
            *gran = response.getUint32(4);
        } else {
            *gran = 0;
        }
    }
    return lastRC;
}

uint8_t DtaDevOpal::loadPBA(const char* password, const char* filename) {
	LOG(D1) << "Entering DtaDevOpal::loadPBAimage()" << filename << " " << dev;
	uint8_t lastRC;
	uint32_t blockSize;
	uint32_t filepos = 0;
	uint32_t eofpos;

    if (testOversizePacket) {
        blockSize = MIN((MAX_BUFFER_LENGTH - 2048), tperMaxPacket);
        if (blockSize > (tperMaxToken - 4)) blockSize = tperMaxToken - 4;
        blockSize += 2048;
    } else {
        blockSize = MIN(PROP_BUFFER_LENGTH, tperMaxPacket);
        if (blockSize > (tperMaxToken - 4)) blockSize = tperMaxToken - 4;
    }
    blockSize -= sizeof(OPALHeader) + 50;  // packet overhead

    std::vector<uint8_t> buffer, lengthtoken;
	buffer.resize(blockSize);

	ifstream pbafile;
	pbafile.open(filename, ios::in | ios::binary);
	if (!pbafile) {
		LOG(E) << "Unable to open PBA image file " << filename;
		return DTAERROR_OPEN_ERR;
	}
	pbafile.seekg(0, pbafile.end);
	eofpos = (uint32_t) pbafile.tellg();
	pbafile.seekg(0, pbafile.beg);

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, OPAL_UID::OPAL_ADMIN1_UID)) != 0) {
		delete session;
		pbafile.close();
		return lastRC;
	}

    uint32_t gran = 0;
    std::vector<uint8_t> tableTableUID = { 0x0A8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x04 };
    getTableWriteGranularity(tableTableUID, &gran);
    if (gran > 1) {
        LOG(I) << "MandatoryWriteGranularity reported as " << gran << ", adjusting token size";
        blockSize -= blockSize % gran;
        buffer.resize(blockSize);
    }

    LOG(I) << "Writing PBA to " << dev << " using token size of " << blockSize;

	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}

	while (!pbafile.eof()) {
		if (eofpos == filepos) break;
		if ((eofpos - filepos) < blockSize) {
			blockSize = eofpos - filepos; // handle a short last block
			buffer.resize(blockSize);
		}
		lengthtoken.clear();
		lengthtoken.push_back(0xe2);
		lengthtoken.push_back((uint8_t) ((blockSize >> 16) & 0x000000ff));
		lengthtoken.push_back((uint8_t)((blockSize >> 8) & 0x000000ff));
		lengthtoken.push_back((uint8_t)(blockSize & 0x000000ff));
		pbafile.read((char *)buffer.data(), blockSize);
		cmd->reset(OPAL_UID::OPAL_MBR, OPAL_METHOD::SET);
		cmd->addToken(OPAL_TOKEN::STARTLIST);
		cmd->addToken(OPAL_TOKEN::STARTNAME);
		cmd->addToken(OPAL_TOKEN::WHERE);
		cmd->addToken(filepos);
		cmd->addToken(OPAL_TOKEN::ENDNAME);
		cmd->addToken(OPAL_TOKEN::STARTNAME);
		cmd->addToken(OPAL_TOKEN::VALUES);
		cmd->addToken(lengthtoken);
		cmd->addToken(buffer);
		cmd->addToken(OPAL_TOKEN::ENDNAME);
		cmd->addToken(OPAL_TOKEN::ENDLIST);
		cmd->complete();
		if ((lastRC = session->sendCommand(cmd, response)) != 0) {
			delete cmd;
			delete session;
			pbafile.close();
			return lastRC;
		}
		filepos += blockSize;
		cout << filepos << " of " << eofpos << " " << (uint16_t) (((float)filepos/(float)eofpos) * 100)
             << "% blk=" << blockSize << " \r";
	}
	cout << "\n";
	delete cmd;
	delete session;
	pbafile.close();
	LOG(I) << "PBA image  " << filename << " written to " << dev;
	LOG(D1) << "Exiting DtaDevOpal::loadPBAimage()";
	return 0;
}

uint8_t DtaDevOpal::readMBR(const char* password, const uint32_t offset, const uint32_t count)
{
    uint8_t buffer[PROP_BUFFER_LENGTH];
    uint8_t  lastRC = 0;

    // Set the table UID to the MBR table UID
    std::vector<uint8_t> tableUID;
    tableUID.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
    for (int i = 0; i < 8; i++) {
        tableUID.push_back(OPALUID[OPAL_UID::OPAL_MBR][i]);
    }

    session = new DtaSession(this);
    if (NULL == session) {
        LOG(E) << "Unable to create session object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }
    if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, OPAL_UID::OPAL_ADMIN1_UID)) != 0) {
        LOG(E) << "session->start failed with code " << HEXON(1) << (int)lastRC << HEXOFF;
        delete session;
        return lastRC;
    }

    uint32_t chunkSize = 0;
    uint32_t bytesRead = 0;

    // Calculate the maximum number of rows we can request in a single Call
    // that will fit in a response packet.
    uint32_t maxChunkSize = MIN((tperMaxPacket - RESPONSE_COM_OVERHEAD),
                                (tperMaxToken - MAX_TOKEN_OVERHEAD));
    if (maxChunkSize > (PROP_BUFFER_LENGTH - (RESPONSE_COM_OVERHEAD + MAX_TOKEN_OVERHEAD))) {
        maxChunkSize = PROP_BUFFER_LENGTH - (RESPONSE_COM_OVERHEAD + MAX_TOKEN_OVERHEAD);
    }

    for (bytesRead = 0; bytesRead < count; bytesRead += chunkSize) {
        chunkSize = MIN(count - bytesRead, maxChunkSize);

        lastRC = getByteTable(tableUID, offset + bytesRead, chunkSize, buffer);
        if (lastRC != 0) {
            LOG(E) << "Read MBR Failure at offset " << bytesRead;
            break;
        }

        if (outputFileName == NULL) {
            DtaHexDump(buffer, chunkSize);
        } else {
            SendToOutputFile(buffer, chunkSize);
        }
    }

    delete session;

    return lastRC;
}

uint8_t DtaDevOpal::loadDataStore(const char* password, const uint8_t table, const uint32_t offset,
                                  const uint32_t count, const char* filename)
{
    LOG(D1) << "Entering DtaDevOpal::loadDataStore()" << filename << " " << dev;

    if (table == 0) {
        LOG(W) << "loadDataStore requested table 0.  The first table is 1.  This is probably not going to work.";
    }

    // Set the table UID to the DataStore table UID using the table argument.
    std::vector<uint8_t> tableUID;
    tableUID.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
    for (int i = 0; i < 8; i++) {
        if (i == 3) {
            tableUID.push_back(table);
        } else {
            tableUID.push_back(OPALUID[OPAL_UID::OPAL_DATASTORE][i]);
        }
    }

    uint8_t lastRC;
    uint32_t filepos = 0;
    uint32_t byteCount = count;
    uint32_t blockSize;

    if (testOversizePacket) {
        blockSize = MIN((MAX_BUFFER_LENGTH - 2048), tperMaxPacket);
        if (blockSize > (tperMaxToken - 4)) blockSize = tperMaxToken - 4;
        blockSize += 2048;
    } else {
        blockSize = MIN(PROP_BUFFER_LENGTH, tperMaxPacket);
        if (blockSize > (tperMaxToken - 4)) blockSize = tperMaxToken - 4;
    }
    blockSize -= sizeof(OPALHeader) + 50;  // packet overhead

    std::vector<uint8_t> buffer, lengthtoken;
    buffer.resize(blockSize);

    ifstream fileStream;
    fileStream.open(filename, ios::in | ios::binary);
    if (!fileStream) {
        LOG(E) << "Unable to open DataStore file " << filename;
        return DTAERROR_OPEN_ERR;
    }
    fileStream.seekg(0, fileStream.end);
    uint32_t eofpos = (uint32_t)fileStream.tellg();
    fileStream.seekg(0, fileStream.beg);

    if (byteCount == 0) {
        byteCount = eofpos;
    }

    session = new DtaSession(this);
    if (NULL == session) {
        LOG(E) << "Unable to create session object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }
    if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, OPAL_UID::OPAL_ADMIN1_UID)) != 0) {
        delete session;
        fileStream.close();
        return lastRC;
    }

    uint32_t gran = 0;
    std::vector<uint8_t> tableTableUID = { 0x0A8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10 };
    tableTableUID.push_back(table);
    getTableWriteGranularity(tableTableUID, &gran);
    if (gran > 1) {
        LOG(I) << "MandatoryWriteGranularity reported as " << gran << ", adjusting token size";
        blockSize -= blockSize % gran;
        buffer.resize(blockSize);
    }

    LOG(I) << "Writing DataStore to " << dev << " using token size of " << blockSize;

    DtaCommand *cmd = new DtaCommand();
    if (NULL == cmd) {
        LOG(E) << "Unable to create command object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }

    uint32_t bytesWritten = 0;
    while (bytesWritten < byteCount) {
        buffer.clear();
        // last chunk handling
        if (blockSize > (byteCount - bytesWritten)) {
            blockSize = byteCount - bytesWritten;
        }
        buffer.resize(blockSize);
        // Fill the buffer with data from the file.  If the file is smaller than the blockSize
        // cycle through the file until we have read blockSize bytes.
        uint32_t bytesFilled = 0;
        uint32_t bufferOffset = 0;
        for (; bufferOffset < blockSize; bufferOffset += bytesFilled) {
            // Fill the buffer to either the end of the file or the end of the buffer, 
            // whichever is less
            bytesFilled = eofpos - filepos;
            if (bytesFilled > (blockSize - bufferOffset)) {
                bytesFilled = blockSize - bufferOffset;
            }
            fileStream.read((char*)buffer.data() + bufferOffset, bytesFilled);
            filepos = (uint32_t)fileStream.tellg();
            if (filepos >= eofpos) {
                fileStream.seekg(0, fileStream.beg);
                filepos = 0;
            }
        }

        lengthtoken.clear();
        lengthtoken.push_back(0xe2);
        lengthtoken.push_back((uint8_t) ((blockSize >> 16) & 0x000000ff));
        lengthtoken.push_back((uint8_t)((blockSize >> 8) & 0x000000ff));
        lengthtoken.push_back((uint8_t)(blockSize & 0x000000ff));

        cmd->reset(tableUID, OPAL_METHOD::SET);
        cmd->addToken(OPAL_TOKEN::STARTLIST);
        cmd->addToken(OPAL_TOKEN::STARTNAME);
        cmd->addToken(OPAL_TOKEN::WHERE);
        cmd->addToken(bytesWritten + offset);
        cmd->addToken(OPAL_TOKEN::ENDNAME);
        cmd->addToken(OPAL_TOKEN::STARTNAME);
        cmd->addToken(OPAL_TOKEN::VALUES);
        cmd->addToken(lengthtoken);
        cmd->addToken(buffer);
        cmd->addToken(OPAL_TOKEN::ENDNAME);
        cmd->addToken(OPAL_TOKEN::ENDLIST);
        cmd->complete();
        if ((lastRC = session->sendCommand(cmd, response)) != 0) {
            delete cmd;
            delete session;
            fileStream.close();
            return lastRC;
        }
        bytesWritten += blockSize;
        cout << bytesWritten << " of " << byteCount << " "
             << (uint16_t)(((float)bytesWritten/(float)byteCount) * 100) << "% blk="
             << blockSize << " \r";
    }
    cout << "\n";
    delete cmd;
    delete session;
    fileStream.close();
    LOG(I) << bytesWritten << " bytes from file " << filename << " written to DataStore on " << dev;
    LOG(D1) << "Exiting DtaDevOpal::loadDataStore()";
    return 0;
}

uint8_t DtaDevOpal::readDataStore(const char* password, const uint8_t table, const uint32_t offset,
                                  const uint32_t count)
{
    uint8_t buffer[PROP_BUFFER_LENGTH];
    uint8_t  lastRC = 0;

    if (table == 0) {
        LOG(W) << "readDataStore requested table 0.  The first table is 1.  This is probably not going to work.";
    }

    // Set the table UID to the DataStore table UID
    std::vector<uint8_t> tableUID;
    tableUID.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
    for (int i = 0; i < 8; i++) {
        if (i == 3) {
            tableUID.push_back(table);
        } else {
            tableUID.push_back(OPALUID[OPAL_UID::OPAL_DATASTORE][i]);
        }
    }

    session = new DtaSession(this);
    if (NULL == session) {
        LOG(E) << "Unable to create session object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }
    if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, OPAL_UID::OPAL_ADMIN1_UID)) != 0) {
        LOG(E) << "session->start failed with code " << HEXON(1) << (int)lastRC << HEXOFF;
        delete session;
        return lastRC;
    }

    uint32_t chunkSize = 0;
    uint32_t bytesRead = 0;

    // Calculate the maximum number of rows we can request in a single Call
    // that will fit in a response packet.
    uint32_t maxChunkSize = MIN((tperMaxPacket - RESPONSE_COM_OVERHEAD),
                                (tperMaxToken - MAX_TOKEN_OVERHEAD));
    if (maxChunkSize > (PROP_BUFFER_LENGTH - (RESPONSE_COM_OVERHEAD + MAX_TOKEN_OVERHEAD))) {
        maxChunkSize = PROP_BUFFER_LENGTH - (RESPONSE_COM_OVERHEAD + MAX_TOKEN_OVERHEAD);
    }

    for (bytesRead = 0; bytesRead < count; bytesRead += chunkSize) {
        chunkSize = MIN(count - bytesRead, maxChunkSize);

        lastRC = getByteTable(tableUID, offset + bytesRead, chunkSize, buffer);
        if (lastRC != 0) {
            LOG(E) << "Read DataStore Failure at offset " << bytesRead;
            break;
        }

        if (outputFileName == NULL) {
            DtaHexDump(buffer, chunkSize);
        } else {
            SendToOutputFile(buffer, chunkSize);
        }
    }

    delete session;

    return lastRC;
}

uint8_t DtaDevOpal::getByteTable(const std::vector<uint8_t>& tableUID, const uint32_t row,
                                 const uint32_t count, uint8_t* buffer)
{
	LOG(D1) << "Entering DtaDevOpal::getByteTable";
	uint8_t lastRC;
	DtaCommand *get = new DtaCommand();
	if (NULL == get) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	get->reset(tableUID, OPAL_METHOD::GET);
	get->addToken(OPAL_TOKEN::STARTLIST);
	get->addToken(OPAL_TOKEN::STARTLIST);
	get->addToken(OPAL_TOKEN::STARTNAME);
	get->addToken(OPAL_TOKEN::STARTROW);
	get->addToken(row);
	get->addToken(OPAL_TOKEN::ENDNAME);
	get->addToken(OPAL_TOKEN::STARTNAME);
	get->addToken(OPAL_TOKEN::ENDROW);
	get->addToken(row + count - 1);
	get->addToken(OPAL_TOKEN::ENDNAME);
	get->addToken(OPAL_TOKEN::ENDLIST);
	get->addToken(OPAL_TOKEN::ENDLIST);
	get->complete();
	if ((lastRC = session->sendCommand(get, response)) != 0) {
		delete get;
		return lastRC;
	}

	response.getBytes(1, buffer);

	delete get;
	return 0;
}

uint8_t DtaDevOpal::activateLockingSP(const char* password, const uint32_t dsCount,
                                      const uint32_t dsSizes[])
{
	LOG(D1) << "Entering DtaDevOpal::activateLockingSP()";
	uint8_t lastRC;
	vector<uint8_t> table;
	table. push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		table.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGSP_UID][i]);
	}
	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_ADMINSP_UID, password, OPAL_UID::OPAL_SID_UID)) != 0) {
		delete cmd;
		delete session;
		return lastRC;
	}
	if ((lastRC = getTable(table, 0x06, 0x06)) != 0) {
		LOG(E) << "Unable to determine LockingSP Lifecycle state";
		delete cmd;
		delete session;
		return lastRC;
	}
	if ((0x06 != response.getUint8(3)) || // getlifecycle
		(0x08 != response.getUint8(4))) // Manufactured-Inactive
	{
		LOG(E) << "Locking SP lifecycle is not Manufactured-Inactive";
		delete cmd;
		delete session;
		return DTAERROR_INVALID_LIFECYCLE;
	}
	cmd->reset(OPAL_UID::OPAL_LOCKINGSP_UID, OPAL_METHOD::ACTIVATE);
	cmd->addToken(OPAL_TOKEN::STARTLIST);
    // If the user has provided a list of DataStore table sizes. add the list as the parameter
    // 0x060002 (DataStoreTableSizes).  See TCG Opal Feature Set - Additional Data Store Tables.
    if (dsCount != 0) {
        cmd->addToken(OPAL_TOKEN::STARTNAME);
            cmd->addToken(OPAL_SHORT_ATOM::UINT_3);
            cmd->addToken(OPAL_TINY_ATOM::UINT_06);
            cmd->addToken(OPAL_TINY_ATOM::UINT_00);
            cmd->addToken(OPAL_TINY_ATOM::UINT_02);
            cmd->addToken(OPAL_TOKEN::STARTLIST);
                for (uint32_t i = 0; i < dsCount; i++) {
                    cmd->addToken((uint64_t)dsSizes[i]);
                }
            cmd->addToken(OPAL_TOKEN::ENDLIST);
        cmd->addToken(OPAL_TOKEN::ENDNAME);
    }
    cmd->addToken(OPAL_TOKEN::ENDLIST);
	cmd->complete();
	if ((lastRC = session->sendCommand(cmd, response)) != 0) {
		delete cmd;
		delete session;
		return lastRC;
	}
	LOG(I) << "Locking SP Activate Complete";

	delete cmd;
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::activatLockingSP()";
	return 0;
}

uint8_t DtaDevOpal::activateLockingSP_SUM(const std::vector<uint32_t>& ranges, const uint32_t policy,
                                          const char* password, const uint32_t dsCount, const uint32_t dsSizes[])
{
	LOG(D1) << "Entering DtaDevOpal::activateLockingSP_SUM()";
	uint8_t lastRC;
	vector<uint8_t> table;
	table.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		table.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGSP_UID][i]);
	}
	uint32_t lockingrange = ranges.front();
	vector<uint8_t> LR;
    // if the lockingrange is -1, then use the Locking Table UID instead of a single row
    if (lockingrange == (uint32_t)(-1)) {
		LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
        for (int i = 0; i < 8; i++) {
            LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKING_TABLE][i]);
        }
    }
	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_ADMINSP_UID, password, OPAL_UID::OPAL_SID_UID)) != 0) {
        LOG(E) << "session->start failed with code " << HEXON(1) << (int)lastRC << HEXOFF;
		delete cmd;
		delete session;
		return lastRC;
	}
	if ((lastRC = getTable(table, 0x06, 0x06)) != 0) {
		LOG(E) << "Unable to determine LockingSP Lifecycle state";
		delete cmd;
		delete session;
		return lastRC;
	}
	if ((0x06 != response.getUint8(3)) || // getlifecycle
		(0x08 != response.getUint8(4))) // Manufactured-Inactive
	{
		LOG(E) << "Locking SP lifecycle is not Manufactured-Inactive";
		delete cmd;
		delete session;
		return DTAERROR_INVALID_LIFECYCLE;
	}
	/*if (!disk_info.SingleUser)
	{
		LOG(E) << "This Locking SP does not support Single User Mode";
		delete cmd;
		delete session;
		return DTAERROR_INVALID_COMMAND;
	}*/
	cmd->reset(OPAL_UID::OPAL_LOCKINGSP_UID, OPAL_METHOD::ACTIVATE);
	cmd->addToken(OPAL_TOKEN::STARTLIST);
		cmd->addToken(OPAL_TOKEN::STARTNAME);
			//SingleUserModeSelectionList parameter
			cmd->addToken(OPAL_SHORT_ATOM::UINT_3);
			cmd->addToken(OPAL_TINY_ATOM::UINT_06);
			cmd->addToken(OPAL_TINY_ATOM::UINT_00);
			cmd->addToken(OPAL_TINY_ATOM::UINT_00);
			if (lockingrange == (uint32_t)-1) {
				cmd->addToken(LR);
			} else {
				cmd->addToken(OPAL_TOKEN::STARTLIST);
				for (int j = 0; j < (int)ranges.size(); j++) {
					lockingrange = ranges.at(j);
					LR.clear();
					LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
					for (int i = 0; i < 8; i++) {
						LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
					}
					if (lockingrange > 0) {
						LR[6] = 0x03;
						LR[8] = lockingrange;
					}
					cmd->addToken(LR);
				}
				cmd->addToken(OPAL_TOKEN::ENDLIST);
			}
		cmd->addToken(OPAL_TOKEN::ENDNAME);
		cmd->addToken(OPAL_TOKEN::STARTNAME);
			// RangeStartRangeLength parameter
			cmd->addToken(OPAL_SHORT_ATOM::UINT_3);
			cmd->addToken(OPAL_TINY_ATOM::UINT_06);
			cmd->addToken(OPAL_TINY_ATOM::UINT_00);
			cmd->addToken(OPAL_TINY_ATOM::UINT_01);
			cmd->addToken(policy);
		cmd->addToken(OPAL_TOKEN::ENDNAME);
        // If the user has provided a list of DataStore table sizes. add the list as the parameter
        // 0x060003 (DataStoreTableSizes).  See TCG Opal Feature Set - Additional Data Store Tables.
        if (dsCount != 0) {
            cmd->addToken(OPAL_TOKEN::STARTNAME);
                cmd->addToken(OPAL_SHORT_ATOM::UINT_3);
                cmd->addToken(OPAL_TINY_ATOM::UINT_06);
                cmd->addToken(OPAL_TINY_ATOM::UINT_00);
                cmd->addToken(OPAL_TINY_ATOM::UINT_03);
                cmd->addToken(OPAL_TOKEN::STARTLIST);
                    for (uint32_t i = 0; i < dsCount; i++) {
                        cmd->addToken((uint64_t)dsSizes[i]);
                    }
                cmd->addToken(OPAL_TOKEN::ENDLIST);
            cmd->addToken(OPAL_TOKEN::ENDNAME);
        }
    cmd->addToken(OPAL_TOKEN::ENDLIST);
	cmd->complete();
	if ((lastRC = session->sendCommand(cmd, response)) != 0) {
		LOG(E) << "session->sendCommand failed with code " << HEXON(1) << (int)lastRC << HEXOFF;
		delete cmd;
		delete session;
		return lastRC;
	}
	disk_info.Locking_lockingEnabled = 1;

	if (lockingrange == (uint32_t)(-1)) {
		LOG(I) << "Locking SP Activate Complete in single-user mode for all locking ranges.";
	} else {
		LOG(I) << "Locking SP Activate Complete in single user mode for the following users/locking ranges:";
		for (int j = 0; j < (int)ranges.size(); j++) {
			lockingrange = ranges.at(j);
			LOG(I) << "    User" << (int)(lockingrange + 1) << " on locking range " << (int)lockingrange;
		}
	}

	delete cmd;
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::activateLockingSP_SUM()";
	return 0;
}

uint8_t DtaDevOpal::reactivateLockingSP_SUM(const char* authority, const char* password,
                                            const std::vector<uint32_t>& ranges, const uint32_t policy,
                                            const uint32_t dsCount, const uint32_t dsSizes[])
{
	LOG(D1) << "Entering DtaDevOpal::reactivateLockingSP_SUM()";
	uint8_t lastRC;
    vector<uint8_t> authorityUID;
    if ((lastRC = getAuth4User(OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
        LOG(E) << "Invalid Authority provided " << authority;
        return lastRC;
    }
	vector<uint8_t> table;
	table.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		table.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGSP_UID][i]);
	}
	uint32_t lockingrange = ranges.front();
	vector<uint8_t> LR;
    // if the lockingrange is -1, then use the Locking Table UID instead of a single row
    if (lockingrange == (uint32_t)(-1)) {
		LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
        for (int i = 0; i < 8; i++) {
            LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKING_TABLE][i]);
        }
    }
	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}

	// start a session ot the LockingSP
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, authorityUID)) != 0) {
        LOG(E) << "session->start failed with code " << HEXON(1) << (int)lastRC << HEXOFF;
		delete cmd;
		delete session;
		return lastRC;
	}
	cmd->reset(OPAL_UID::OPAL_THISSP_UID, OPAL_METHOD::REACTIVATE);
	cmd->addToken(OPAL_TOKEN::STARTLIST);
	if (lockingrange != (uint32_t)-2) {
		cmd->addToken(OPAL_TOKEN::STARTNAME);
		//SingleUserModeSelectionList parameter
		cmd->addToken(OPAL_SHORT_ATOM::UINT_3);
		cmd->addToken(OPAL_TINY_ATOM::UINT_06);
		cmd->addToken(OPAL_TINY_ATOM::UINT_00);
		cmd->addToken(OPAL_TINY_ATOM::UINT_00);
		if (lockingrange == (uint32_t)-1) {
			cmd->addToken(LR);
		} else {
			cmd->addToken(OPAL_TOKEN::STARTLIST);
			for (int j = 0; j < (int)ranges.size(); j++) {
				lockingrange = ranges.at(j);
				LR.clear();
				LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
				for (int i = 0; i < 8; i++) {
					LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
				}
				if (lockingrange > 0) {
					LR[6] = 0x03;
					LR[8] = lockingrange;
				}
				cmd->addToken(LR);
			}
			cmd->addToken(OPAL_TOKEN::ENDLIST);
		}
		cmd->addToken(OPAL_TOKEN::ENDNAME);
		cmd->addToken(OPAL_TOKEN::STARTNAME);
			// RangeStartRangeLength parameter
			cmd->addToken(OPAL_SHORT_ATOM::UINT_3);
			cmd->addToken(OPAL_TINY_ATOM::UINT_06);
			cmd->addToken(OPAL_TINY_ATOM::UINT_00);
			cmd->addToken(OPAL_TINY_ATOM::UINT_01);
			cmd->addToken(policy);
		cmd->addToken(OPAL_TOKEN::ENDNAME);
	}
    // If the user has provided a list of DataStore table sizes. add the list as the parameter
    // 0x060003 (DataStoreTableSizes).  See TCG Opal Feature Set - Additional Data Store Tables.
    if (dsCount != 0) {
        cmd->addToken(OPAL_TOKEN::STARTNAME);
            cmd->addToken(OPAL_SHORT_ATOM::UINT_3);
            cmd->addToken(OPAL_TINY_ATOM::UINT_06);
            cmd->addToken(OPAL_TINY_ATOM::UINT_00);
            cmd->addToken(OPAL_TINY_ATOM::UINT_03);
            cmd->addToken(OPAL_TOKEN::STARTLIST);
            for (uint32_t i = 0; i < dsCount; i++) {
                cmd->addToken((uint64_t)dsSizes[i]);
            }
            cmd->addToken(OPAL_TOKEN::ENDLIST);
        cmd->addToken(OPAL_TOKEN::ENDNAME);
    }
    cmd->addToken(OPAL_TOKEN::ENDLIST);
	cmd->complete();
	if ((lastRC = session->sendCommand(cmd, response)) != 0) {
		LOG(E) << "session->sendCommand failed with code " << HEXON(1) << (int)lastRC << HEXOFF;
		delete cmd;
		delete session;
		return lastRC;
	}
	disk_info.Locking_lockingEnabled = 1;

	if (lockingrange == (uint32_t)(-1)) {
		LOG(I) << "Locking SP Reactivate Complete in single user mode for all locking ranges.";
	} else if (lockingrange == (uint32_t)(-2)) {
		LOG(I) << "Locking SP Reactivate Complete with no locking ranges in single user mode.";
	} else {
		LOG(I) << "Locking SP Activate Complete in single user mode for the following users/locking ranges:";
		for (int j = 0; j < (int)ranges.size(); j++) {
			lockingrange = ranges.at(j);
			LOG(I) << "    User" << (int)(lockingrange + 1) << " on locking range " << (int)lockingrange;
		}
	}

	delete cmd;
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::reactivateLockingSP_SUM()";
	return 0;
}

uint8_t DtaDevOpal::eraseLockingRange_SUM(const char* authority, const uint8_t lockingrange,
										  const char* password)
{
	uint8_t lastRC;
	LOG(D1) << "Entering DtaDevOpal::eraseLockingRange_SUM";

    vector<uint8_t> authorityUID;
    if ((lastRC = getAuth4User(OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
        LOG(E) << "Invalid Authority provided " << authority;
        return lastRC;
    }

	vector<uint8_t> LR;
	LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
	}
	if (lockingrange != 0) {
		LR[6] = 0x03;
		LR[8] = lockingrange;
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, authorityUID)) != 0) {
		delete session;
		return lastRC;
	}

	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	cmd->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::ERASE);
	cmd->changeInvokingUid(LR);
	cmd->addToken(OPAL_TOKEN::STARTLIST);
	cmd->addToken(OPAL_TOKEN::ENDLIST);
	cmd->complete();
	if ((lastRC = session->sendCommand(cmd, response)) != 0) {
		LOG(E) << "setLockingRange Failed ";
		delete cmd;
		delete session;
		return lastRC;
	}
	delete cmd;
	delete session;
	LOG(I) << "LockingRange" << (uint16_t)lockingrange << " erased";
	LOG(D1) << "Exiting DtaDevOpal::eraseLockingRange_SUM";
	return 0;
}

uint8_t DtaDevOpal::lockLockingRange_SUM(const char* authority, const char* password,
                                         const uint8_t lockingrange)
{
    LOG(D1) << "Entering DtaDevOpal::lockLockingRange_SUM";

    uint8_t lastRC;
    vector<uint8_t> authorityUID;

    if ((lastRC = getAuth4User(OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
        LOG(E) << "Invalid Authority provided " << authority;
        return lastRC;
    }

    vector<uint8_t> LR;
    LR.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
    for (int i = 0; i < 8; i++) {
        LR.push_back(OPALUID[OPAL_UID::OPAL_LOCKINGRANGE_GLOBAL][i]);
    }
    if (lockingrange != 0) {
        LR[6] = 0x03;
        LR[8] = lockingrange;
    }

    session = new DtaSession(this);
    if (NULL == session) {
        LOG(E) << "Unable to create session object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }
    if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, authorityUID)) != 0) {
        delete session;
        return lastRC;
    }

    DtaCommand *cmd = new DtaCommand();
    if (NULL == cmd) {
        LOG(E) << "Unable to create command object ";
        delete session;
        return DTAERROR_OBJECT_CREATE_FAILED;
    }

    cmd->reset(LR, OPAL_METHOD::LOCK);
    cmd->addToken(OPAL_TOKEN::STARTLIST);
    cmd->addToken(OPAL_TOKEN::ENDLIST);
    cmd->complete();

    if ((lastRC = session->sendCommand(cmd, response)) != 0) {
        LOG(E) << "setLockingRange Failed ";
    } else {
        LOG(I) << "LockingRange" << (uint16_t)lockingrange << " locked";
        LOG(D1) << "Exiting DtaDevOpal::lockLockingRange_SUM";
    }
    delete cmd;
    delete session;
    return lastRC;
}

uint8_t DtaDevOpal::setFeatureLocking(const char* authority, const char* password,
                                      const uint8_t column, const uint8_t value)
{
    LOG(D1) << "Entering DtaDevOpal::setFeatureLocking";

    uint8_t lastRC;
    vector<uint8_t> authorityUID;

    if ((lastRC = getAuth4User(OPAL_UID::OPAL_ADMINSP_UID, authority, 0, authorityUID)) != 0) {
        LOG(E) << "Invalid Authority provided " << authority;
        return lastRC;
    }

    session = new DtaSession(this);
    if (NULL == session) {
        LOG(E) << "Unable to create session object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }

    if ((lastRC = session->start(OPAL_UID::OPAL_ADMINSP_UID, password, authorityUID)) != 0) {
        delete session;
        return lastRC;
    }

    vector<uint8_t> table = {OPAL_SHORT_ATOM::BYTESTRING8, 0xFF, 0xFF, 0, 1, 0, 0, 0, 1};

    if ((lastRC = setTable(table, (OPAL_TOKEN)column, (OPAL_TOKEN)value)) != 0) {
        delete session;
        return lastRC;
    }

    delete session;
    return lastRC;
}

uint8_t DtaDevOpal::takeOwnership(const char* newpassword)
{
	LOG(D1) << "Entering DtaDevOpal::takeOwnership()";
	uint8_t lastRC;
	if ((lastRC = getDefaultPassword()) != 0) {
		LOG(E) << "Unable to read MSID password ";
		return lastRC;
	}
	if ((lastRC = setSIDPassword((char *)response.getString(4).c_str(), newpassword, 0)) != 0) {
		LOG(E) << "takeOwnership failed";
		return lastRC;
	}
	LOG(I) << "takeOwnership complete";
	LOG(D1) << "Exiting takeOwnership()";
	return 0;
}
uint8_t DtaDevOpal::getDefaultPassword()
{
	LOG(D1) << "Entering DtaDevOpal::getDefaultPassword()";
	uint8_t lastRC;
	vector<uint8_t> hash;
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_ADMINSP_UID)) != 0) {
		LOG(E) << "Unable to start Unauthenticated session " << dev;
		delete session;
		return lastRC;
	}

    vector<uint8_t> table;
	table. push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		table.push_back(OPALUID[OPAL_UID::OPAL_C_PIN_MSID][i]);
	}
	if ((lastRC = getTable(table, PIN, PIN)) != 0) {
		delete session;
		return lastRC;
	}
	delete session;
	LOG(D1) << "Exiting getDefaultPassword()";
	return 0;
}
uint8_t DtaDevOpal::printDefaultPassword()
{
    const uint8_t rc = getDefaultPassword();
	if (rc) {
		LOG(E) << "unable to read MSID password";
		return rc;
	}
	const std::string defaultPassword = response.getString(4);
    fprintf(stdout, "MSID: %s\n", defaultPassword.c_str());
    return 0;
}
uint8_t DtaDevOpal::setSIDPassword(const char* oldpassword, const char* newpassword,
                                   const uint8_t hasholdpwd, const uint8_t hashnewpwd)
{
	vector<uint8_t> hash, table;
	LOG(D1) << "Entering DtaDevOpal::setSIDPassword()";
	uint8_t lastRC;
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if (!hasholdpwd) session->dontHashPwd();
	if ((lastRC = session->start(OPAL_UID::OPAL_ADMINSP_UID,
		oldpassword, OPAL_UID::OPAL_SID_UID)) != 0) {
		delete session;
		return lastRC;
	}
	table.clear();
	table. push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		table.push_back(OPALUID[OPAL_UID::OPAL_C_PIN_SID][i]);
	}
	hash.clear();
	if (hashnewpwd) {
		DtaHashPwd(hash, newpassword, this);
	}
	else {
		hash.push_back(0xd0);
		hash.push_back((uint8_t)strnlen(newpassword, 255));
		for (uint16_t i = 0; i < strnlen(newpassword, 255); i++) {
			hash.push_back(newpassword[i]);
		}
	}
	if ((lastRC = setTable(table, OPAL_TOKEN::PIN, hash)) != 0) {
		LOG(E) << "Unable to set new SID password ";
		delete session;
		return lastRC;
	}
	LOG(I) << "SID password changed";
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::setSIDPassword()";
	return 0;
}

uint8_t DtaDevOpal::enableTperReset(const char* password, const uint8_t options)
{
	LOG(D1) << "Entering DtaDevOpal::enableTperReset";
	uint8_t lastRC;
    OPAL_TOKEN enable = (options == OPAL_LOCKINGSTATE::DISABLERESET) ? OPAL_TOKEN::OPAL_FALSE
                                                                     : OPAL_TOKEN::OPAL_TRUE;

	vector<uint8_t> table;
	table. push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		table.push_back(OPALUID[TPER_INFO_TABLE][i]);
	}
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start(OPAL_UID::OPAL_ADMINSP_UID, password, OPAL_UID::OPAL_SID_UID)) == 0) {
        if ((lastRC = setTable(table, OPAL_TOKEN::TPERRESETENABLE, enable)) != 0) {
            LOG(E) << "Unable to update the TperInfo table";
        }
	}

	delete session;
	LOG(D1) << "Exiting DtaDevOpal::enableTperReset";
	return lastRC;
}

uint8_t DtaDevOpal::clearDoneOnReset(const char* authority, const char* password, const uint8_t options)
{
	LOG(D1) << "Entering DtaDevOpal::clearDoneOnReset";
	uint8_t lastRC;

    vector<uint8_t> authorityUID;
    if ((lastRC = getAuth4User(OPAL_UID::OPAL_LOCKINGSP_UID, authority, 0, authorityUID)) != 0) {
        LOG(E) << "Invalid Authority provided " << authority;
        return lastRC;
    }

	vector<uint8_t> table;
	table. push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		table.push_back(OPALUID[OPAL_MBRCONTROL][i]);
	}

	vector<uint8_t> column_list;
    column_list.push_back(OPAL_TOKEN::STARTLIST);
    column_list.push_back(OPAL_TOKEN::POWER_CYCLE);
    if (options == OPAL_LOCKINGSTATE::ENABLERESET) {
        column_list.push_back(OPAL_TOKEN::PROGRAMMATIC);
    }
    column_list.push_back(OPAL_TOKEN::ENDLIST);

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}

	if ((lastRC = session->start(OPAL_UID::OPAL_LOCKINGSP_UID, password, OPAL_UID::OPAL_ADMIN1_UID)) == 0) {
        if ((lastRC = setTable(table, OPAL_TOKEN::MBRDONEONRESET, column_list)) != 0) {
            LOG(E) << "Unable to update the MBR Control table";
        }
	}

	delete session;
	LOG(D1) << "Exiting DtaDevOpal::clearDoneOnReset";
	return lastRC;
}

uint8_t DtaDevOpal::getACE(const char* sp, const char* authority, const char* password, const uint32_t halfRow)
{
    LOG(D1) << "Entering DtaDevOpal::getACE";
    uint8_t lastRC;
    std::vector<uint8_t> authorityUID;

    OPAL_UID spuid = (sp[0] == 'A') ? OPAL_UID::OPAL_ADMINSP_UID : OPAL_UID::OPAL_LOCKINGSP_UID;

    if ((lastRC = getAuth4User(spuid, authority, 0, authorityUID)) != 0) {
        LOG(E) << "Invalid Authority provided " << authority;
        return lastRC;
    }

    std::vector<uint8_t> tableRow = {OPAL_SHORT_ATOM::BYTESTRING8, 0x00, 0x00, 0x00, 0x08,
                                     (uint8_t)(halfRow >> 24),
                                     (uint8_t)(halfRow >> 16),
                                     (uint8_t)(halfRow >>  8),
                                     (uint8_t)(halfRow >>  0)};

    session = new DtaSession(this);
    if (NULL == session) {
        LOG(E) << "Unable to create session object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }

    if ((lastRC = session->start(spuid, password, authorityUID)) != 0) {
        delete session;
        return lastRC;
    }
    if ((lastRC = getTable(tableRow, (OPAL_TOKEN)0x03, (OPAL_TOKEN)0x04)) != 0) {
        LOG(E) << "Unable to Get from table UID 0x00000008" << HEXON(8) << halfRow << HEXOFF;
        delete session;
        return lastRC;
    }

    uint64_t row = 0;
    for (int i = 1; i <= 8; i++) row = (row << 8) + tableRow[i];
    printf("Row: 0x%016lx, value:", row);

    uint32_t name = 0;
    uint64_t value = 0;
    uint8_t bytes[16];
    int count;
    for (unsigned int index = 5; index < response.getTokenCount(); ) {
        if (response.tokenIs(index) == OPAL_TOKEN::STARTNAME) {
            count = response.getBytes(++index, bytes);
            for (int i = 0; i < count; i++) name = (name << 8) + bytes[i];
            if (name == 0x00000C05) {
                count = response.getBytes(++index, bytes);
                for (int i = 0; i < count; i++) value = (value << 8) + bytes[i];
                printf(" UID: 0x%016lx", value);
            }
            else if (name == 0x0000040E) {
                value = response.getUint64(++index);
                printf(" LOGIC: ");
                if (value == 0) {
                    printf("AND");
                } else if (value == 1) {
                    printf("OR");
                } else if (value == 2) {
                    printf("NOT");
                } else {
                    printf("Unknown (0x%lx)", value);
                }
            }
            index += 2;    // skip end name
        }
        else {
            break;
        }
    }
    printf("\n");

    delete session;
    LOG(D1) << "Exiting DtaDevOpal::getACE()";
    return 0;
}

uint8_t DtaDevOpal::setACE(const char* sp, const char* authority, const char* password, const uint32_t halfRow,
                           const char* user)
{
    LOG(D1) << "Entering DtaDevOpal::setACE";
    uint8_t lastRC;
    std::vector<uint8_t> authorityUID;

    OPAL_UID spuid = (sp[0] == 'A') ? OPAL_UID::OPAL_ADMINSP_UID : OPAL_UID::OPAL_LOCKINGSP_UID;

    if ((lastRC = getAuth4User(spuid, authority, 0, authorityUID)) != 0) {
        LOG(E) << "Invalid Authority provided " << authority;
        return lastRC;
    }

    std::vector<uint8_t> tableRow = { OPAL_SHORT_ATOM::BYTESTRING8, 0x00, 0x00, 0x00, 0x08,
                                      (uint8_t)(halfRow >> 24),
                                      (uint8_t)(halfRow >> 16),
                                      (uint8_t)(halfRow >>  8),
                                      (uint8_t)(halfRow >>  0) };

    std::vector<uint8_t> userVec;
    if ((lastRC = getAuth4User(spuid, user, 0, userVec)) != 0) {
        LOG(E) << "Invalid user provided " << user;
        return lastRC;
    }

    std::vector<uint8_t> expression = {OPAL_TOKEN::STARTLIST,
                                       OPAL_TOKEN::STARTNAME,
                                       OPAL_SHORT_ATOM::BYTESTRING4, 0x00, 0x00, 0x0C, 0x05 };
    expression.insert(expression.end(), userVec.begin(), userVec.end());
    expression.push_back(OPAL_TOKEN::ENDNAME);
    expression.push_back(OPAL_TOKEN::ENDLIST);

    session = new DtaSession(this);
    if (NULL == session) {
        LOG(E) << "Unable to create session object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }

    if ((lastRC = session->start(spuid, password, authorityUID)) != 0) {
        delete session;
        return lastRC;
    }
    if ((lastRC = setTable(tableRow, (OPAL_TOKEN)0x03, expression)) != 0) {
        LOG(E) << "Unable to Set from table UID " << HEXON(16) << (uint64_t)halfRow + 0x800000000 << HEXOFF;
        delete session;
        return lastRC;
    }

    delete session;
    LOG(D1) << "Exiting DtaDevOpal::setACE()";

    getACE(sp, authority, password, halfRow);
    return 0;
}

uint8_t DtaDevOpal::getRandom(const char* sp, const char* authority, const char* password,
                              const uint32_t size)
{
    LOG(D1) << "Entering DtaDevOpal::getRandom";
    uint8_t lastRC;
    std::vector<uint8_t> authorityUID;

    OPAL_UID spuid = ((sp[0] == 'A') || (sp[0] == 'a')) ? OPAL_UID::OPAL_ADMINSP_UID :
                                                          OPAL_UID::OPAL_LOCKINGSP_UID;

    if ((lastRC = getAuth4User(spuid, authority, 0, authorityUID)) != 0) {
        LOG(E) << "Invalid Authority provided " << authority;
        return lastRC;
    }

    session = new DtaSession(this);
    if (NULL == session) {
        LOG(E) << "Unable to create session object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }

    if (strncmp(authority, "Anybody", 7) == 0) {
        if ((lastRC = session->start(spuid)) != 0) {
            delete session;
            return lastRC;
        }
    } else {
        if ((lastRC = session->start(spuid, password, authorityUID)) != 0) {
            delete session;
            return lastRC;
        }
    }

    DtaCommand *cmd = new DtaCommand();
    if (NULL == cmd) {
        LOG(E) << "Unable to create command object ";
        delete session;
        return DTAERROR_OBJECT_CREATE_FAILED;
    }

    cmd->reset(OPAL_UID::OPAL_THISSP_UID, OPAL_METHOD::RANDOM);
    cmd->addToken(OPAL_TOKEN::STARTLIST);
    cmd->addToken((uint64_t)size);
    cmd->addToken(OPAL_TOKEN::ENDLIST);
    cmd->complete();
    if ((lastRC = session->sendCommand(cmd, response)) != 0) {
        delete cmd;
        delete session;
        return lastRC;
    }

    if ((response.getTokenCount() > 3) && response.isByteSequence(1)) {
        uint32_t returnBytes = response.getLength(1);
        if (returnBytes > 512) {
            LOG(E) << "Error decoding Random response, size = " << returnBytes;
        } else {
            uint8_t array[512];
            uint32_t returnedBytes = response.getBytes(1, array);
            for (uint32_t i = 0; i < returnedBytes; i++) {
                printf("%02x", array[i]);
            }
            printf("\n");
        }
    }

    delete cmd;
    delete session;
    LOG(D1) << "Exiting DtaDevOpal::getRandom()";
    return 0;
}

uint8_t DtaDevOpal::setTable(const std::vector<uint8_t>& table, const OPAL_TOKEN name,
                             const OPAL_TOKEN value)
{
	vector <uint8_t> token;
	token.push_back((uint8_t) value);
	return(setTable(table, name, token));
}

uint8_t DtaDevOpal::setTable(const std::vector<uint8_t>& table, const OPAL_TOKEN name,
                             const std::vector<uint8_t>& value)
{
	LOG(D1) << "Entering DtaDevOpal::setTable";
	uint8_t lastRC;
	DtaCommand *set = new DtaCommand();
	if (NULL == set) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	set->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::SET);
	set->changeInvokingUid(table);
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(OPAL_TOKEN::VALUES); // "values"
	set->addToken(OPAL_TOKEN::STARTLIST);
	set->addToken(OPAL_TOKEN::STARTNAME);
	set->addToken(name);
    set->addToken(value);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->addToken(OPAL_TOKEN::ENDNAME);
	set->addToken(OPAL_TOKEN::ENDLIST);
	set->complete();
	if ((lastRC = session->sendCommand(set, response)) != 0) {
		LOG(E) << "Set Failed ";
		delete set;
		return lastRC;
	}
	delete set;
	LOG(D1) << "Leaving DtaDevOpal::setTable";
	return 0;
}

uint8_t DtaDevOpal::getTable(const std::vector<uint8_t>& table, const uint32_t startcol,
                             const uint32_t endcol)
{
	LOG(D1) << "Entering DtaDevOpal::getTable";
	uint8_t lastRC;
	DtaCommand *get = new DtaCommand();
	if (NULL == get) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	get->reset(table, OPAL_METHOD::GET);
	get->addToken(OPAL_TOKEN::STARTLIST);
	get->addToken(OPAL_TOKEN::STARTLIST);
	get->addToken(OPAL_TOKEN::STARTNAME);
	get->addToken(OPAL_TOKEN::STARTCOLUMN);
	get->addToken(startcol);
	get->addToken(OPAL_TOKEN::ENDNAME);
	if (endcol != (uint32_t)-1) {
		get->addToken(OPAL_TOKEN::STARTNAME);
		get->addToken(OPAL_TOKEN::ENDCOLUMN);
		get->addToken(endcol);
		get->addToken(OPAL_TOKEN::ENDNAME);
	}
	get->addToken(OPAL_TOKEN::ENDLIST);
	get->addToken(OPAL_TOKEN::ENDLIST);
	get->complete();
	if ((lastRC = session->sendCommand(get, response)) != 0) {
		delete get;
		return lastRC;
	}
	delete get;
	return 0;
}

uint8_t DtaDevOpal::exec(const DtaCommand* cmd, DtaResponse& resp, const uint16_t ComID, const uint8_t protocol)
{
    uint8_t lastRC;
    OPALHeader * hdr = (OPALHeader *) cmd->getCmdBuffer();

    LOG(D3) << endl << "Dumping command buffer";
    IFLOG(D) DtaAnnotatedDump(IF_SEND, cmd->getCmdBuffer(), cmd->outputBufferSize());
    IFLOG(D3) DtaHexDump(cmd->getCmdBuffer(), SWAP32(hdr->cp.length) + sizeof (OPALComPacket));

    uint32_t retryCount = 0;
    do {
        if ((lastRC = sendCmd(IF_SEND, protocol, ComID, cmd->getCmdBuffer(), cmd->outputBufferSize())) == 0) {
            break;
        }
        LOG(E) << "Command failed on send, status code = " << (uint16_t)lastRC;
        if (retryCount >= sendRetries) {
            return lastRC;
        }
        ++retryCount;
        osmsSleep(10);
    } while (true);

    hdr = (OPALHeader *)cmd->getRespBuffer();
    uint32_t receiveLength = (PROP_BUFFER_LENGTH < tperMaxPacket) ? PROP_BUFFER_LENGTH : tperMaxPacket;
    do {
        memset(cmd->getRespBuffer(), 0, receiveLength);
        lastRC = sendCmd(IF_RECV, protocol, ComID, cmd->getRespBuffer(), receiveLength);
        if ((hdr->cp.outstandingData == 0) || (hdr->cp.minTransfer != 0)) {
            break;
        }
        osmsSleep(25);

    } while (lastRC == 0);

    LOG(D3) << std::endl << "Dumping reply buffer";
    IFLOG(D) DtaAnnotatedDump(IF_RECV, cmd->getRespBuffer(), SWAP32(hdr->cp.length) + sizeof (OPALComPacket));
    IFLOG(D3) DtaHexDump(cmd->getRespBuffer(), SWAP32(hdr->cp.length) + sizeof(OPALComPacket));

    // multi-thread option set, delay after the send for other thread to get in.
    if (sendRetries != 0) {
        osmsSleep(20);
    }

    if (0 != lastRC) {
        LOG(E) << "Command failed on recv, status code = " << (uint16_t)lastRC;
        return lastRC;
    }
    resp.init(cmd->getRespBuffer());
    return 0;
}

uint8_t DtaDevOpal::properties()
{
	LOG(D1) << "Entering DtaDevOpal::properties()";
	uint8_t lastRC;
	session = new DtaSession(this);  // use the session IO without starting a session
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	DtaCommand *props = new DtaCommand(OPAL_UID::OPAL_SMUID_UID, OPAL_METHOD::PROPERTIES);
	if (NULL == props) {
		LOG(E) << "Unable to create command object ";
		delete session;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	props->addToken(OPAL_TOKEN::STARTLIST);
	props->addToken(OPAL_TOKEN::STARTNAME);
	props->addToken(OPAL_TOKEN::HOSTPROPERTIES);
	props->addToken(OPAL_TOKEN::STARTLIST);
	props->addToken(OPAL_TOKEN::STARTNAME);
	props->addToken("MaxComPacketSize");
	props->addToken(PROP_BUFFER_LENGTH);
	props->addToken(OPAL_TOKEN::ENDNAME);
	props->addToken(OPAL_TOKEN::STARTNAME);
	props->addToken("MaxResponseComPacketSize");
	props->addToken(PROP_BUFFER_LENGTH);
	props->addToken(OPAL_TOKEN::ENDNAME);
	props->addToken(OPAL_TOKEN::STARTNAME);
	props->addToken("MaxPacketSize");
	props->addToken(PROP_BUFFER_LENGTH);
	props->addToken(OPAL_TOKEN::ENDNAME);
	props->addToken(OPAL_TOKEN::STARTNAME);
	props->addToken("MaxIndTokenSize");
	props->addToken(PROP_BUFFER_LENGTH - 56);
	props->addToken(OPAL_TOKEN::ENDNAME);
	props->addToken(OPAL_TOKEN::STARTNAME);
	props->addToken("MaxPackets");
	props->addToken(1);
	props->addToken(OPAL_TOKEN::ENDNAME);
	props->addToken(OPAL_TOKEN::STARTNAME);
	props->addToken("MaxSubpackets");
	props->addToken(1);
	props->addToken(OPAL_TOKEN::ENDNAME);
	props->addToken(OPAL_TOKEN::STARTNAME);
	props->addToken("MaxMethods");
	props->addToken(1);
	props->addToken(OPAL_TOKEN::ENDNAME);
	props->addToken(OPAL_TOKEN::ENDLIST);
	props->addToken(OPAL_TOKEN::ENDNAME);
	props->addToken(OPAL_TOKEN::ENDLIST);
	props->complete();
	if ((lastRC = session->sendCommand(props, propertiesResponse)) != 0) {
		delete props;
		return lastRC;
	}
	disk_info.Properties = 1;
	delete props;
	for (uint32_t i = 0; i < propertiesResponse.getTokenCount(); i++) {
		if (OPAL_TOKEN::STARTNAME == propertiesResponse.tokenIs(i)) {
			if (OPAL_TOKEN::DTA_TOKENID_BYTESTRING != propertiesResponse.tokenIs(i + 1))
				break;
			else
				if(!strcasecmp("MaxComPacketSize",propertiesResponse.getString(i + 1).c_str()))
					tperMaxPacket = propertiesResponse.getUint32(i + 2);
				else
					if (!strcasecmp("MaxIndTokenSize", propertiesResponse.getString(i + 1).c_str())) {
						tperMaxToken = propertiesResponse.getUint32(i + 2);
						break;
					}

			i += 2;
		}
	}
	LOG(D1) << "Leaving DtaDevOpal::properties()";
	return 0;
}
void DtaDevOpal::puke()
{
	LOG(D1) << "Entering DtaDevOpal::puke()";
	DtaDev::puke();
	if (disk_info.Properties) {
		cout << std::endl << "TPer Properties: ";
		for (uint32_t i = 0; i < propertiesResponse.getTokenCount(); i++) {
			if (OPAL_TOKEN::STARTNAME == propertiesResponse.tokenIs(i)) {
				if (OPAL_TOKEN::DTA_TOKENID_BYTESTRING != propertiesResponse.tokenIs(i + 1))
					cout << std::endl << "Host Properties: " << std::endl;
				else
					cout << "  " << propertiesResponse.getString(i + 1) << " = " << propertiesResponse.getUint64(i + 2);
				i += 2;
			}
			if (!(i % 6)) cout << std::endl;
		}
	}
    printSecurityCompliance();
}

uint8_t DtaDevOpal::objDump(const char* sp, const char* auth, const char* pass,
                            const char* objID)
{

	LOG(D1) << "Entering DtaDevOpal::objDump";
	LOG(D1) << sp << " " << auth << " " << pass << " " << objID;
	uint8_t lastRC;
	DtaCommand *get = new DtaCommand();
	if (NULL == get) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	vector<uint8_t> authority, object;
	uint8_t work;
	if (16 != strnlen(auth, 32)) {
		LOG(E) << "Authority must be 16 byte ascii string of hex authority uid";
		return DTAERROR_INVALID_PARAMETER;
	}
	if (16 != strnlen(objID, 32)) {
		LOG(E) << "ObjectID must be 16 byte ascii string of hex object uid";
		return DTAERROR_INVALID_PARAMETER;
	}
	authority.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (uint32_t i = 0; i < 16; i += 2) {
		work = auth[i] & 0x40 ? 16 * ((auth[i] & 0xf) + 9) : 16 * (auth[i] & 0x0f);
		work += auth[i + 1] & 0x40 ? (auth[i + 1] & 0xf) + 9 : auth[i + 1] & 0x0f;
		authority.push_back(work);
	}
	object.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (uint32_t i = 0; i < 16; i += 2) {
		work = objID[i] & 0x40 ? 16 * ((objID[i] & 0xf) + 9) : 16 * (objID[i] & 0x0f);
		work += objID[i + 1] & 0x40 ? (objID[i + 1] & 0xf) + 9 : objID[i + 1] & 0x0f;
		object.push_back(work);
	}
	get->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, OPAL_METHOD::GET);
	get->changeInvokingUid(object);
	get->addToken(OPAL_TOKEN::STARTLIST);
	get->addToken(OPAL_TOKEN::STARTLIST);
	get->addToken(OPAL_TOKEN::ENDLIST);
	get->addToken(OPAL_TOKEN::ENDLIST);
	get->complete();
	LOG(I) << "Command:";
	get->dumpCommand();
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		delete get;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start((OPAL_UID)atoi(sp), pass, authority)) != 0) {
		delete get;
		delete session;
		return lastRC;
	}
	if ((lastRC = session->sendCommand(get, response)) != 0) {
		delete get;
		delete session;
		return lastRC;
	}
	LOG(I) << "Response:";
	get->dumpResponse();
	delete get;
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::objDump";
	return 0;
}

uint8_t DtaDevOpal::rawCmd(const char* sp, const char* hexauth, const char* pass,
                           const char* hexinvokingUID, const char* hexmethod, const char* hexparms)
{
	LOG(D1) << "Entering DtaDevOpal::rawCmd";
	LOG(D1) << sp << " " << hexauth << " " << pass << " ";
	LOG(D1) << hexinvokingUID << " " << hexmethod << " " << hexparms;
	uint8_t lastRC;
	vector<uint8_t> authority, object, invokingUID, method, parms;
	uint8_t work;
	if (16 != strnlen(hexauth, 32)) {
		LOG(E) << "Authority must be 16 byte ascii string of hex authority uid";
		return DTAERROR_INVALID_PARAMETER;
	}
	authority.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (uint32_t i = 0; i < 16; i += 2) {
		work = hexauth[i] & 0x40 ? 16 * ((hexauth[i] & 0xf) + 9) : 16 * (hexauth[i] & 0x0f);
		work += hexauth[i + 1] & 0x40 ? (hexauth[i + 1] & 0xf) + 9 : hexauth[i + 1] & 0x0f;
		authority.push_back(work);
	}
	if (16 != strnlen(hexinvokingUID, 32)) {
		LOG(E) << "invoker must be 16 byte ascii string of invoking uid";
		return DTAERROR_INVALID_PARAMETER;
	}
	invokingUID.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (uint32_t i = 0; i < 16; i += 2) {
		work = hexinvokingUID[i] & 0x40 ? 16 * ((hexinvokingUID[i] & 0xf) + 9) : 16 * (hexinvokingUID[i] & 0x0f);
		work += hexinvokingUID[i + 1] & 0x40 ? (hexinvokingUID[i + 1] & 0xf) + 9 : hexinvokingUID[i + 1] & 0x0f;
		invokingUID.push_back(work);
	}
	if (16 != strnlen(hexmethod, 32)) {
		LOG(E) << "invoker must be 16 byte ascii string of method uid";
		return DTAERROR_INVALID_PARAMETER;
	}
	method.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (uint32_t i = 0; i < 16; i += 2) {
		work = hexmethod[i] & 0x40 ? 16 * ((hexmethod[i] & 0xf) + 9) : 16 * (hexmethod[i] & 0x0f);
		work += hexmethod[i + 1] & 0x40 ? (hexmethod[i + 1] & 0xf) + 9 : hexmethod[i + 1] & 0x0f;
		method.push_back(work);
	}
	if (1020 < strnlen(hexparms, 1024)) {
		LOG(E) << "Parmlist limited to 1020 characters";
		return DTAERROR_INVALID_PARAMETER;
	}
	if (strnlen(hexparms, 1024) % 2) {
		LOG(E) << "Parmlist must be even number of bytes";
		return DTAERROR_INVALID_PARAMETER;
	}

	for (uint32_t i = 0; i < strnlen(hexparms, 1024); i += 2) {
		work = hexparms[i] & 0x40 ? 16 * ((hexparms[i] & 0xf) + 9) : 16 * (hexparms[i] & 0x0f);
		work += hexparms[i + 1] & 0x40 ? (hexparms[i + 1] & 0xf) + 9 : hexparms[i + 1] & 0x0f;
		parms.push_back(work);
	}
	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	cmd->reset(OPAL_UID::OPAL_AUTHORITY_TABLE, method);
	cmd->changeInvokingUid(invokingUID);
	cmd->addToken(parms);
	cmd->complete();
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		delete cmd;
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	if ((lastRC = session->start((OPAL_UID)atoi(sp), pass, authority)) != 0) {
		delete cmd;
		delete session;
		return lastRC;
	}
	LOG(I) << "Command:";
	cmd->dumpCommand();
	if ((lastRC = session->sendCommand(cmd, response)) != 0) {
		delete cmd;
		delete session;
		return lastRC;
	}
	LOG(I) << "Response:";
	cmd->dumpResponse();
	delete cmd;
	delete session;
	LOG(D1) << "Exiting DtaDevOpal::rawCmd";
	return 0;
}

//
// Print Tables code.
//
const tableDesc_t UnknownTableDesc =
{
    "Unknown",
    "",
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    1,
    1,
    1,
    {
        { 0, "UID" }
    }
};

const tableDesc_t TableTableDesc =
{
    "Table",
    "",
    { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 },
    1,
    0,
    15,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "TemplateID" },
        { 4, "Kind" },
        { 5, "Column" },
        { 6, "NumCol" },
        { 7, "Rows" },
        { 8, "RowsFree" },
        { 9, "RowBytes" },
        { 10, "LastID" },
        { 11, "MinSize" },
        { 12, "MaxSize" },
        { 13, "MadatoryWriteGran" },
        { 14, "RecomendWriteGran" }
    }
};

const tableDesc_t SPInfoTableDesc =
{
    "SPInfo",
    "",
    { 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,              // skip
    7,
    {
        { 0, "UID" },
        { 1, "SPID" },
        { 2, "Name" },
        { 3, "Size" },
        { 4, "SizeInUse" },
        { 5, "SPSessionTimeout" },
        { 6, "Enabled" }
    }
};

const tableDesc_t SPTemplateTableDesc =
{
    "SPTemplate",
    "",
    { 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,              // skip
    4,
    {
        { 0, "UID" },
        { 1, "TemplateID" },
        { 2, "Name" },
        { 3, "Version" }
    }
};

const tableDesc_t ColumnTableDesc =
{
    "Column",
    "",
    { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,              // skip
    9,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "Type" },
        { 4, "IsUnique" },
        { 5, "ColumnNumber" },
        { 6, "Transactional" },
        { 7, "Next" },
        { 8, "AttributeFlags" }
    }
};

const tableDesc_t MethodIDTableDesc =
{
    "MethodID",
    "",
    { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,              // skip
    4,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "TemplateID" }
    }
};

const tableDesc_t AccessControlTableDesc =
{
    "AccessControl",
    "",
    { 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,              // skip
    15,
    {
        { 0, "UID" },
        { 1, "InvokingID" },
        { 2, "MethodID" },
        { 3, "CommonName" },
        { 4, "ACL" },
        { 5, "Log" },
        { 6, "AddACEACL" },
        { 7, "RemoveACEACL" },
        { 8, "GetACLACL" },
        { 9, "DeleteMethodACL" },
        { 10, "AddACELog" },
        { 11, "RemoveACELog" },
        { 12, "GetACLLog" },
        { 13, "DeleteMethodLog" },
        { 14, "LogTo" }
    }
};

const tableDesc_t ACETableDesc =
{
    "ACE",
    "An <empty List> value in the 'columns' column indicates the entry applies to all columns.",
    { 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,              // skip
    5,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "BooleanExpr" },
        { 4, "Columns" }
    }
};

const tableDesc_t AuthorityTableDesc =
{
    "Authority",
    "",
    { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,              // skip
    19,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "IsClass" },
        { 4, "Class" },
        { 5, "Enabled" },
        { 6, "Secure" },
        { 7, "HashAndSign" },
        { 8, "PresentCertificate" },
        { 9, "Operation" },
        { 10, "Credential" },
        { 11, "ResponseSign" },
        { 12, "ResponseExch" },
        { 13, "ClockStart" },
        { 14, "ClockEnd" },
        { 15, "Limit" },
        { 16, "Uses" },
        { 17, "Log" },
        { 18, "LogTo" }
    }
};

const tableDesc_t C_PINTableDesc =
{
    "C_PIN",
    "",
    { 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    8,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "PIN" },
        { 4, "CharSet" },
        { 5, "TryLimit" },
        { 6, "Tries" },
        { 7, "Persistence" }
    }
};

const tableDesc_t C_HMAC_384TableDesc =
{
    "C_HMAC_384",
    "",
    { 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    5,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "Key" },
        { 4, "Hash" }
    }
};

const tableDesc_t SecretProtectTableDesc =
{
    "SecretProtect",
    "",
    { 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    4,
    {
        { 0, "UID" },
        { 1, "Table" },
        { 2, "ColumnNumber" },
        { 3, "ProtectMechanisms" }
    }
};

const tableDesc_t C_TLS_PSKTableDesc =
{
    "C_TLS_PSK",
    "Defined in Core Specification Secure Messaging addendum.",
    { 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    6,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "Enabled" },
        { 4, "PSK" },
        { 5, "CipherSuite" }
    }
};

const tableDesc_t TPerInfoTableDesc =
{
    "TPerInfo",
    "",
    { 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x02, 0x01, 0x00, 0x03, 0x00, 0x01 },
    1,
    0,                  // skip
    9,
    {
        { 0, "UID" },
        { 1, "Bytes" },
        { 2, "GUDID" },
        { 3, "Generation" },
        { 4, "FirmwareVersion" },
        { 5, "ProtocolVersion" },
        { 6, "SpaceForIssuance" },
        { 7, "SSC" },
        { 8, "ProgResetEnable" }
    }
};

const tableDesc_t TemplateTableDesc =
{
    "Template",
    "",
    { 0x00, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    5,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "RevisionNumber" },
        { 3, "Instances" },
        { 4, "MaxInstances" }
    }
};

const tableDesc_t SPTableDesc =
{
    "SP",
    "",
    { 0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                      // skip
    8,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "Org" },
        { 3, "EffectiveAuth" },
        { 4, "DateOfIssue" },
        { 5, "Bytes" },
        { 6, "LifeCycleState" },
        { 7, "Frozen" }
    }
};

const tableDesc_t LockingInfoTableDesc =
{
    "LockingInfo",
    "",
    { 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    11,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "Version" },
        { 3, "EncryptionSupport" },
        { 4, "MaxRanges" },
        { 5, "MaxReEncryptions" },
        { 6, "KeysAvailableConfig" },
        { 7, "AlignmentRequired" },
        { 8, "LogicalBlockSize" },
        { 9, "AlignmentGranularity" },
        { 10, "LowestAlignedLBA" }
    }
};

const tableDesc_t LockingTableDesc =
{
    "Locking",
    "",
    { 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    22,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "RangeStart" },
        { 4, "RangeLength" },
        { 5, "RdLkEnabled" },
        { 6, "WrLkEnabled" },
        { 7, "RdLocked" },
        { 8, "WrLocked" },
        { 9, "LkOnReset" },
        { 10, "ActiveKey" },
        { 11, "NextKey" },
        { 12, "ReEncState" },
        { 13, "ReEncReq" },
        { 14, "AdvKeyMode" },
        { 15, "VerifyMode" },
        { 16, "ContOnReset" },
        { 17, "LastReEncLBA" },
        { 18, "LastReEncState" },
        { 19, "GeneralStatus" },
        { 20, "NamespaceID" },
        { 21, "NamespaceGlobal" }
    }
};

const tableDesc_t MBRControlTableDesc =
{
    "MBRControl",
    "",
    { 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    5,
    {
        { 0, "UID" },
        { 1, "Enable" },
        { 2, "Done" },
        { 3, "DoneOnReset" },
        { 4, "NamespaceID" }
    }
};

const tableDesc_t MBRTableDesc =
{
    "MBR",
    "",
    { 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00 },
    0,
    0,                      // skip
    0,
    {}
};

const tableDesc_t K_AES_128TableDesc =
{
    "K_AES_128",
    "",
    { 0x00, 0x00, 0x08, 0x05, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x08, 0x05, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                      // skip
    5,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "Key" },
        { 4, "Mode" }
    }
};

const tableDesc_t K_AES_256TableDesc =
{
    "K_AES_256",
    "",
    { 0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    5,
    {
        { 0, "UID" },
        { 1, "Name" },
        { 2, "CommonName" },
        { 3, "Key" },
        { 4, "Mode" }
    }
};

const tableDesc_t DataStoreTableDesc =
{
    "DataStore",
    "",
    { 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00 },
    0,
    0,                      // skip
    0,
    {}
};

const tableDesc_t VUFeatureLockingTableDesc =
{
    "VU Feature Locking",
    "Vendor Unique Feature Locking Table.",
    { 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 },
    { 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 },
    1,
    0,                  // skip
    4,
    {
        { 0, "UID" },
        { 1, "FWDownload" },
        { 2, "VUCommands" },
        { 3, "MinFeatures" }
    }
};

const tableDesc_t* tableDescriptors[] =
{
	// Defined in TCG Storage Architecture
	&TableTableDesc,
	&SPInfoTableDesc,
	&SPTemplateTableDesc,
    &ColumnTableDesc,
	&MethodIDTableDesc,
	&AccessControlTableDesc,
	&ACETableDesc,
	&AuthorityTableDesc,
	&C_PINTableDesc,
    &C_HMAC_384TableDesc,
	&SecretProtectTableDesc,
    &C_TLS_PSKTableDesc,
	&TPerInfoTableDesc,
	&TemplateTableDesc,
	&SPTableDesc,
	// Defined in Opal SSC
	&LockingInfoTableDesc,
	&LockingTableDesc,
	&MBRControlTableDesc,
	&MBRTableDesc,
	&K_AES_128TableDesc,
	&K_AES_256TableDesc,
	&DataStoreTableDesc,
	// Vendor Unique
	&VUFeatureLockingTableDesc
};

int anybody;
int authenticated;
int failed;

uint8_t DtaDevOpal::verifyPassword(const OPAL_UID sp, const OPAL_UID authority, const std::string& pw)
{
	LOG(D1) << "Entering DtaDevOpal::verifyPassword()";

	uint8_t lastRC = 0xff;

	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}

	if (pw.length() != 0) {
		if ((lastRC = session->start(sp, pw.c_str(), authority)) != 0) {
			LOG(E) << "Unable to start session" << dev;
		} else {
            std::vector<uint8_t> auth(OPALUID[authority], OPALUID[authority] + 8);
            auth.insert(auth.begin(), OPAL_SHORT_ATOM::BYTESTRING8);
            lastRC = session->authenticate(auth, pw.c_str());
        }
	}

    deleteSession();
	LOG(D1) << "Exiting verifyPassword()";
	return lastRC;
}

uint8_t DtaDevOpal::nextTable(const std::vector<uint8_t>& table)
{
	LOG(D1) << "Entering DtaDevOpal::nextTable";
	uint8_t lastRC;
	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create command object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}

	std::vector<uint8_t> tableTok(table);
	tableTok.insert(tableTok.begin(), OPAL_SHORT_ATOM::BYTESTRING8);

	cmd->reset(tableTok, OPAL_METHOD::NEXT);
	cmd->addToken(OPAL_TOKEN::STARTLIST);
	cmd->addToken(OPAL_TOKEN::ENDLIST);
	cmd->complete();

	lastRC = session->sendCommand(cmd, response);
	delete cmd;
	return lastRC;
}

uint8_t DtaDevOpal::nextTableRow(const OPAL_UID sp, const OPAL_UID auth, const std::string& pw,
                                 const std::vector<uint8_t>& tableUID)
{
	LOG(D1) << "Entering DtaDevOpal::()";
	uint8_t lastRC;
	vector<uint8_t> hash;
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}

	if (pw.length() != 0) {
		if ((lastRC = session->start(sp, (char*)pw.c_str(), auth)) != 0) {
			LOG(E) << "Unable to start Admin session " << dev;
		}
	}
	else if ((lastRC = session->start(sp, NULL,
									  OPAL_UID::OPAL_ANYBODY_UID)) != 0) {
		LOG(E) << "Unable to start Anybody session " << dev;
		deleteSession();
		return lastRC;
	}

	if ((lastRC = nextTable(tableUID)) != 0) {
		deleteSession();
		return lastRC;
	}
	deleteSession();
	LOG(D1) << "Exiting nextTableRow()";
	return 0;
}

// Get and entire table row
uint8_t DtaDevOpal::getTable(const std::vector<uint8_t>& table)
{
    LOG(D1) << "Entering DtaDevOpal::getTable";
    uint8_t lastRC;
    DtaCommand *get = new DtaCommand();
    if (NULL == get) {
        LOG(E) << "Unable to create command object ";
        return DTAERROR_OBJECT_CREATE_FAILED;
    }
    get->reset(table, OPAL_METHOD::GET);
    get->addToken(OPAL_TOKEN::STARTLIST);
        get->addToken(OPAL_TOKEN::STARTLIST);
            get->addToken(OPAL_TOKEN::STARTNAME);
                get->addToken(OPAL_TOKEN::STARTCOLUMN);
                get->addToken((uint64_t)0);
            get->addToken(OPAL_TOKEN::ENDNAME);
        get->addToken(OPAL_TOKEN::ENDLIST);
    get->addToken(OPAL_TOKEN::ENDLIST);
    get->complete();
    if ((lastRC = session->sendCommand(get, response)) != 0) {
        delete get;
        return lastRC;
    }
    delete get;
    return 0;
}

uint8_t DtaDevOpal::getTableRow(const std::vector<uint8_t>& uid,
								const tableDesc_t* TableDesc,
								const OPAL_UID sp,
								const OPAL_UID auth,
								const std::string& password,
								rowMap_t& rowMap,
								const uint8_t level)
{
	LOG(D1) << "Entering DtaDevOpal::getTableRow()";\

	if (level > 1) {
		cout << "\nGetTable contents for table row ";
		printUID(uid);
		printf("h, columns 0 through %d\n", TableDesc->columnCount - 1);
	}

	uint8_t lastRC = 1;

	std::vector<uint8_t> uidtok(uid);
	uidtok.insert(uidtok.begin(), OPAL_SHORT_ATOM::BYTESTRING8);

    if (session == NULL)
    {
        if (password.length() != 0)
        {
            if (level > 2) cout << "Attempting password authentication.\n";
            session = new DtaSession(this);
            if (NULL == session) {
                LOG(E) << "Unable to create session object ";
                return DTAERROR_OBJECT_CREATE_FAILED;
            }
            if ((lastRC = session->start(sp, (char*)password.c_str(), auth)) != 0) {
                if (level > 2) cout << "Unable to start authenticated session.\n";
                deleteSession();
            } else {
                if (level > 2) cout << "Session opened with password authentication.\n";
                if ((lastRC = getTable(uidtok)) != 0) {
                    deleteSession();
                }
                authenticated++;
            }
        }

        if (lastRC != 0) {
            // Try as anybody
            if (level > 2) cout << "Attempting anybody authorization.\n";
            session = new DtaSession(this);
            if (NULL == session) {
                LOG(E) << "Unable to create session object ";
                return DTAERROR_OBJECT_CREATE_FAILED;
            }
            if ((lastRC = session->start(sp, NULL, OPAL_UID::OPAL_ANYBODY_UID)) != 0) {
                if (level > 2) cout << "Unable to start anybody session.\n";
            } else {
                if (level > 2) cout << "Session opened with Anybody authorization.\n";
                lastRC = getTable(uidtok);
                if (lastRC == 0) {
                    anybody++;
                }
            }
        }
    }
    else
    {
        if (level > 2) cout << "Session already open.\n";
        lastRC = getTable(uidtok);
    }

	if (lastRC != 0) {
		deleteSession();
		failed++;
		return lastRC;
	}

	uint32_t tokenCount = response.getTokenCount();
	for (uint32_t i = 0; i < tokenCount; i++) {
		OPAL_TOKEN tokenType = response.tokenIs(i);
		if (tokenType == OPAL_TOKEN::STARTNAME) {
			char valueStr[140] = "<empty list>";
			char* valuePtr = valueStr;
            const char* columnName = "Unknown";

			// the first entry after a start name in the column number
			uint32_t column = response.getUint32(++i);
            if (column < TableDesc->columnCount) {
                columnName = TableDesc->columns.find(column)->second.c_str();
            }
			// if the column number is followed by a start list token, then
			// the column contains a list of values.
			if (response.tokenIs(++i) == OPAL_TOKEN::STARTLIST) {
				while (response.tokenIs(++i) != OPAL_TOKEN::ENDLIST) {
					// skip end name tokens
					if (response.tokenIs(i) == OPAL_TOKEN::ENDNAME) {
						continue;
					}
					// look for start name token
					if (response.tokenIs(i) == OPAL_TOKEN::STARTNAME) {
						// if the previous token was a end name, add a ',' to
						// the output stream.
						if (response.tokenIs(i-1) == OPAL_TOKEN::ENDNAME) {
							valuePtr += sprintf(valuePtr, ", ");
						}
						continue;
					}
					// If the previous token was not a start name, add a space.
					if (response.tokenIs(i-1) != OPAL_TOKEN::STARTNAME &&
					    response.tokenIs(i-1) != OPAL_TOKEN::STARTLIST) {
						valuePtr += sprintf(valuePtr, " ");
					}

					uint32_t valueLength = response.getLength(i);

					if (valueLength <= 4) {
						valuePtr += sprintf(valuePtr, "%xh", response.getUint32(i));
					} else {
						uint8_t buffer[64];
						char    str[140];

						int size = response.getBytes(i, buffer);
						printBytes(buffer, size, str);
						valuePtr += sprintf(valuePtr, "%s", str);
					}
				}
				if (level > 1) {
					printf("  Column: %2d, Name: '%s', Value (list): %s\n",
					   column, columnName, valueStr); 
				}
			}
			else {
                if (response.isByteSequence(i) == 0) {
					if (level > 1) {
						printf("  Column: %2d, Name: '%s', Value: %lxh\n",
						       column, columnName, response.getUint64(i));
					}
					sprintf(valueStr, "%lxh", response.getUint64(i));
				} else {
					uint8_t buffer[64];
					char    str[140];

					int size = response.getBytes(i, buffer);
					printBytes(buffer, size, str);
					if (level > 1) {
						printf("  Column: %2d, Name: '%s', Value: %s\n",
						       column, columnName, str);
					}
					sprintf(valueStr, "%s", str);
				}
			}
			rowMap[column] = valueStr;
		}
	}

    // If the first column is UID and we did not get a value returned for that
    // column, then add the row UID in that place with a 'H' instead of 'h'.
    if ((TableDesc->columns.find(0)->second.compare(0, 3, "UID") == 0) && 
        (rowMap[0].compare("N/A") == 0)) {
        printUID(uid, rowMap[0]);
        rowMap[0].push_back('H');
    }

	LOG(D1) << "Exiting getTableRow()";
	return 0;
}

uint8_t DtaDevOpal::getACLCmd(const std::vector<uint8_t>& object,
							  const std::vector<uint8_t>& method)
{
	LOG(D1) << "Entering DtaDevOpal::getACLCmd";

	std::vector<uint8_t> methodTok(method);
	methodTok.insert(methodTok.begin(), OPAL_SHORT_ATOM::BYTESTRING8);

	std::vector<uint8_t> uidTok(object);
	uidTok.insert(uidTok.begin(), OPAL_SHORT_ATOM::BYTESTRING8);

	uint8_t lastRC;
	DtaCommand *get = new DtaCommand();
	if (NULL == get) {
		LOG(E) << "Unable to create command object";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	get->reset(OPAL_UID::ACCESS_CONTROL_TABLE, OPAL_METHOD::GETACL);
	get->addToken(OPAL_TOKEN::STARTLIST);
	get->addToken(uidTok);
	get->addToken(methodTok);
	get->addToken(OPAL_TOKEN::ENDLIST);
	get->complete();
	if ((lastRC = session->sendCommand(get, response)) != 0) {
		delete get;
		return lastRC;
	}
	delete get;
	return 0;
}

uint8_t DtaDevOpal::getACL(const std::vector<uint8_t>& object,
						   const std::vector<uint8_t>& method,
						   std::string& str,
						   const uint8_t level)
{
	uint8_t lastRC = getACLCmd(object, method);
	if (lastRC != 0) {
		return lastRC;
	}

	char valueStr[100] = "<empty list>";
	char* valuePtr = valueStr;
	uint32_t tokenCount = response.getTokenCount();
	for (uint32_t i = 0; i < tokenCount; i++) {
		OPAL_TOKEN tokenType = response.tokenIs(i);

		if (tokenType == OPAL_TOKEN::STARTLIST) {
			continue;
		} else if (tokenType == OPAL_TOKEN::ENDLIST) {
			break;

		} else {
			uint32_t valueLength = response.getLength(i);

			if (valuePtr != valueStr) {
				valuePtr += sprintf(valuePtr, " ");
			}

			if (valueLength <= 4) {
				valuePtr += sprintf(valuePtr, "%xh", response.getUint32(i));
			} else {
				uint8_t buffer[64];
				char    strVal[140];

				int size = response.getBytes(i, buffer);
				printBytes(buffer, size, strVal);
				valuePtr += sprintf(valuePtr, "%s", strVal);
			}
		}
	}

	str = valueStr;
	return 0;
}

uint8_t DtaDevOpal::getACLRow(const std::vector<uint8_t>& object,
				              const std::vector<std::vector<uint8_t>>& methods,
				              const OPAL_UID sp,
                              const OPAL_UID auth,
                              const std::string& password,
				              tableRows_t& output, 
                              const uint8_t level)
{
	LOG(D1) << "Entering DtaDevOpal::getACLRow()";

	std::string objectStr;
	printUID(object, objectStr);
	objectStr.push_back('h');

	if (level > 1) {
		printf("\nGet ACL for object %s\n", objectStr.c_str());
	}

	if (level > 2) cout << "Attempting anybody authorization.\n";
	session = new DtaSession(this);
	if (NULL == session) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	uint8_t lastRC;
    if ((lastRC = session->start(sp, NULL, OPAL_UID::OPAL_ANYBODY_UID)) != 0) {
		if (level > 2) cout << "Unable to start anybody session.\n";
        failed++;
        return lastRC;
	} else {
		if (level > 2) cout << "Session opened with Anybody authorization.\n";
		anybody++;
	}

	for (auto it = methods.begin(); it != methods.end(); ++it) {
		std::string aclStr;
		lastRC = getACL(object, *it, aclStr, level);
		if ((lastRC == 0 ) && (aclStr.length() != 0)) {
			std::string methodStr;
			printUID(*it, methodStr);
			methodStr.push_back('h');

			rowMap_t entry;
			entry[0] = objectStr;
			entry[1] = methodStr;
			entry[2] = aclStr;

			output.push_back(entry);

			if (level > 1) {
				printf("  Object: %s, Method: %s, Value: %s\n", objectStr.c_str(),
						methodStr.c_str(), aclStr.c_str());
			}
		}
	}

    deleteSession();
	LOG(D1) << "Exiting DtaDevOpal::getACLRow()";

	return 0;
}

void DtaDevOpal::printUID(const std::vector<uint8_t>& uid)
{
	for (auto it = uid.cbegin(); it != uid.cend(); ++it) {
		printf("%02x", *it);
	}
}

void DtaDevOpal::printUID(const std::vector<uint8_t>& uid, std::string& str)
{
	char buffer[20];
	int index = 0;
	for (auto it = uid.cbegin(); it != uid.cend(); ++it) {
		index += sprintf(&buffer[index], "%02x", *it);
	}

	str = buffer;
}

void DtaDevOpal::printUID(const uint8_t* uid)
{
	for (int i = 0; i < 8; i++) {
		printf("%02x", uid[i]);
	}
}

void DtaDevOpal::printBytes(const uint8_t* uid, const int length, char* str)
{
	int index = 0;

	for (int i = 0;;)
	{
		// if all of the bytes are printable, print the string.
		if (isprint(uid[i]) == 0) {
			index = 0;
			break;
		}
		str[index++] = uid[i++];
		if (i == length) {
			str[index] = '\0';
			return;
		}
	}
	// If we got here, some of the bytes are not ASCII, convert hex to ASCII.
	for (int i = 0; i < length; i++) {
		index += sprintf(&str[index], "%02x", uid[i]);
	}
	str[index++] = 'h';
	str[index]   = '\0';
}

uint8_t DtaDevOpal::printTables(const char* sp, const char* password, const uint8_t level)
{
	printf("DtaDevOpal::printTables() called, security provider = %s, password = '%s', level = %d\n",
			sp, password, level);

	if (level < 3) {
		RCLog::Level() = RCLog::FromInt(0);
	}

	std::string spStr("LockingSP");

	anybody = authenticated = failed = 0;

	std::string pw(password);
	if ((sp[0] == 'a') || (sp[0] == 'A')) {
		// Request is for the AdminSP
		spStr = "AdminSP";

		if (pw.length() == 0) {
			// No password was supplied, use the MSID
			if (getDefaultPassword() != 0) {
				printf("Unable to read MSID password\n");
			} else {
				pw = response.getString(4);
				// Since this is the default password, no hashing.
				no_hash_passwords = true;
			}
		}
	}

	if (spStr.compare("AdminSP") == 0) {
		printTablesForSP("AdminSP", OPAL_UID::OPAL_ADMINSP_UID, OPAL_UID::OPAL_SID_UID, pw, level);
	} else {
		printTablesForSP("LockingSP", OPAL_UID::OPAL_LOCKINGSP_UID, OPAL_UID::OPAL_ADMIN1_UID, pw, level);
	}

    if (level > 1) {
        printf("\n\nEnd of table list for Security Provider %s\n", spStr.c_str());
        printf("Statistics: anybody = %d, authenticated = %d, failed = %d\n",
                anybody, authenticated, failed);
    }

	return 0;
}

uint8_t DtaDevOpal::printTablesForSP(const char* spStr, const OPAL_UID sp,
									 const OPAL_UID auth, const std::string& password,
									 const uint8_t level)
{
	printf("***** %s Security Provider ******\n", spStr);

    std::string pw;

	if (verifyPassword(sp, auth, password) != 0) {
		printf("Password verification failed, using Anyone authority.\n");
        pw.clear();
	} else {
		printf("Password verified.\n");
        pw = password;
	}

	printf("\nTable Table\n");

	vector<uint8_t> tableTableUID{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
	uint8_t rc = nextTableRow(sp, auth, pw, tableTableUID);
	if (rc) {
		printf("Unable to read table rows.\n");
		return rc;
	}

	uint32_t tokenCount = response.getTokenCount();

	std::vector<std::vector<uint8_t>> rows;
	for (uint32_t i = 0; i < tokenCount; i++) {
		if (response.tokenIs(i) == DTA_TOKENID_BYTESTRING) {
            uint8_t uid[8];
			response.getBytes(i, uid);
			std::vector<uint8_t> uidv;
			for (int ii = 0; ii < 8; ii++) {
				uidv.push_back(uid[ii]);
			}
			rows.push_back(uidv);
		}
	}
	printf("Returned table table list has %d rows\n", (int)rows.size());
	if (level > 2) {
		for (auto it = rows.cbegin(); it != rows.cend(); it++) {
			printUID(*it);
			cout << "\n";
		}
	}

	// For the ACL, we need the methods list supported by this SP.
	std::vector<std::vector<uint8_t>> methodsList;

	std::vector<uint8_t> methodTable = { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00 };
	rc = nextTableRow(sp, auth, pw, methodTable);
	if (rc) {
		printf("Unable to read MethodID table rows.\n");
	} else {
		tokenCount = response.getTokenCount();
		uint8_t uid[8];
		for (uint32_t i = 0; i < tokenCount; i++) {
			if (response.tokenIs(i) == DTA_TOKENID_BYTESTRING) {
				response.getBytes(i, uid);
				std::vector<uint8_t> uidv;
				for (int ii = 0; ii < 8; ii++) {
					uidv.push_back(uid[ii]);
				}
				methodsList.push_back(uidv);
			}
		}
	}

	printf("Returned MethodID table list has %d rows\n", (int)methodsList.size());
	if (level > 2) {
		for (auto it = methodsList.cbegin(); it != methodsList.cend(); it++) {
			printUID(*it);
			cout << "\n";
		}
	}

	//
	// iterate through the table from the table table
	//
	for (auto it = rows.cbegin(); it != rows.cend(); it++) {
		std::vector<uint8_t> table;
		for (int i = 4; i < 8; i++) {
			table.push_back((*it)[i]);
		}
		for (int i = 4; i < 8; i++) {
			table.push_back(0);
		}

		// Find the table Descriptor.
		const tableDesc_t* tableDescPtr = &UnknownTableDesc;
		for (unsigned int i = 0;
			 i < (sizeof(tableDescriptors) / sizeof(const tableDesc_t*)); i++) {
			if (memcmp(table.data(), tableDescriptors[i]->uid, 8) == 0) {
				tableDescPtr = tableDescriptors[i];
				break;
			}
		}

		printf("\nWorking on %s::%s table (", spStr, tableDescPtr->name);
		printUID(table);
		printf(")\n");

        if (tableDescPtr->skip != 0) {
            printf("Skipping table.\n");
            continue;
        }

        // Get the ACL for this table.
        tableRows_t aclRows;
        getACLRow(table, methodsList, sp, auth, pw, aclRows, level);

		if (tableDescPtr->kind == 0) {
			printf("Table is a byte table, skipping rows.\n");
 		} else {
            std::vector<std::vector<uint8_t>> rowUIDs;

    		uint8_t rc = nextTableRow(sp, auth, pw, table);
    		if (rc) {
    			std::vector<uint8_t> oneRow(tableDescPtr->defaultRow, tableDescPtr->defaultRow + 8);
    			rowUIDs.push_back(oneRow);
                string defaultUID;
                printUID(oneRow, defaultUID);
    			printf("Unable to read table rows list, using the default (%s)\n", defaultUID.c_str());
    		} else {
    			tokenCount = response.getTokenCount();
    			uint8_t uid[8];
    			for (uint32_t i = 0; i < tokenCount; i++) {
    				if (response.tokenIs(i) == DTA_TOKENID_BYTESTRING) {
    					response.getBytes(i, uid);
    					std::vector<uint8_t> uidv;
    					for (int ii = 0; ii < 8; ii++) {
    						uidv.push_back(uid[ii]);
    					}
    					rowUIDs.push_back(uidv);
    				}
    			}
    		}

    		if (level > 1) {
    			printf("Table has the following rows:\n");

    			for (auto itUID = rowUIDs.cbegin(); itUID != rowUIDs.cend(); itUID++) {
    				printUID(*itUID);
    				cout << "\n";
    			}
    		}

    		tableRows_t tableRows;
            session = NULL;

    		// retrieve each row and save the values returned.
    		for (auto itUID = rowUIDs.cbegin(); itUID != rowUIDs.cend(); itUID++) {
    			rowMap_t rowMap;
    			for (uint32_t i = 0; i < tableDescPtr->columnCount; i++) {
    				rowMap[i] = "N/A";
    			}
    			getTableRow(*itUID, tableDescPtr, sp, auth, pw, rowMap, level);
    			tableRows.push_back(rowMap);
    		}
            deleteSession();

    		// Print the table contents as reported.
    		printf("\nTable %s::%s:\n", spStr, tableDescPtr->name);
    		// This first part is calculating column widths based
    		// on the largest string in each column
    		uint32_t columns = tableDescPtr->columnCount;
    		uint32_t columnWidth[32];
    		for (uint32_t i = 0; i < columns; i++) {
    			columnWidth[i] = strlen(tableDescPtr->columns.find(i)->second.c_str()) + 1;
    		}
    		for (auto itRow = tableRows.begin(); itRow != tableRows.cend(); itRow++) {
    			for (uint32_t i = 0; i < columns; i++) {
    				if ((*itRow)[i].length() + 1 > columnWidth[i]) {
    					columnWidth[i] = (*itRow)[i].length() + 1;
    				}
    			}
    		}

    		for (uint32_t i = 0; i < tableDescPtr->columnCount; i++) {
    			printf("%-*s", columnWidth[i], tableDescPtr->columns.find(i)->second.c_str());
    		}
    		for (auto itRow = tableRows.begin(); itRow != tableRows.cend(); itRow++) {
    			printf("\n");
    			for (uint32_t i = 0; i < tableDescPtr->columnCount; i++) {
    				printf("%-*s", columnWidth[i], (*itRow)[i].c_str());
    			}
    		}
    		if (strlen(tableDescPtr->notes)) {
    			printf("\nNote: %s", tableDescPtr->notes);
    		}
    		printf("\nTable %s::%s complete.\n", spStr, tableDescPtr->name);

            if (level > 0) {
                // retrieve ACL values for each row and save the values returned.
                for (auto itUID = rowUIDs.cbegin(); itUID != rowUIDs.cend(); itUID++) {
                    getACLRow(*itUID, methodsList, sp, auth, pw, aclRows, level);
                }
            }
        }

        // Print the ACL
        if (level == 0) {
        }
        else if (aclRows.size() == 0) {
			printf("\nNo ACL entries retrieved for table %s::%s\n",
			       spStr, tableDescPtr->name);
		} else {
			// Calculate the column widths.
			uint32_t columnWidthAcl[3] = {4, 7, 4};
			for (auto itRow = aclRows.begin(); itRow != aclRows.cend(); itRow++) {
				for (uint32_t i = 0; i < 4; i++) {
					if ((*itRow)[i].length() + 1 > columnWidthAcl[i]) {
						columnWidthAcl[i] = (*itRow)[i].length() + 1;
					}
				}
			}

			printf("\nACL for Table %s::%s:\n", spStr, tableDescPtr->name);
			printf("%-*s%-*s%-*s", columnWidthAcl[0], "UID",
			       columnWidthAcl[1], "Method", columnWidthAcl[2], "ACL");
			for (auto itRow = aclRows.begin(); itRow != aclRows.cend(); itRow++) {
				printf("\n");
				for (uint32_t i = 0; i < 3; i++) {
					printf("%-*s", columnWidthAcl[i], (*itRow)[i].c_str());
				}
			}
			printf("\nACL for Table %s::%s complete.\n\n", spStr, tableDescPtr->name);
		}
	}

    if (level > 0) {
        // Print the ACL for this security Protocol
        tableRows_t aclRows;

        // This SP UID
        std::vector<uint8_t> thisUID(OPALUID[OPAL_UID::OPAL_THISSP_UID],
                                     OPALUID[OPAL_UID::OPAL_THISSP_UID] + 8);
        getACLRow(thisUID, methodsList, sp, auth, pw, aclRows, level);

        // Actual SP UID
        std::vector<uint8_t> spUID(OPALUID[sp], OPALUID[sp] + 8);
        getACLRow(spUID, methodsList, sp, auth, pw, aclRows, level);

        if (aclRows.size() == 0) {
            printf("\nNo ACL entries retrieved for Security Protocol %s\n", spStr);
        } else {
            // Calculate the column widths.
            uint32_t columnWidthAcl[3] = {4, 7, 4};
            for (auto itRow = aclRows.begin(); itRow != aclRows.cend(); itRow++) {
                for (uint32_t i = 0; i < 4; i++) {
                    if ((*itRow)[i].length() + 1 > columnWidthAcl[i]) {
                        columnWidthAcl[i] = (*itRow)[i].length() + 1;
                    }
                }
            }

            printf("\nACL for Security Protocol %s\n", spStr);
            printf("%-*s%-*s%-*s", columnWidthAcl[0], "UID",
                   columnWidthAcl[1], "Method", columnWidthAcl[2], "ACL");
            for (auto itRow = aclRows.begin(); itRow != aclRows.cend(); itRow++) {
                printf("\n");
                for (uint32_t i = 0; i < 3; i++) {
                    printf("%-*s", columnWidthAcl[i], (*itRow)[i].c_str());
                }
            }
            printf("\nACL for Security Protocol %s complete.\n\n", spStr);
        }
    }

	return 0;
}

void DtaDevOpal::deleteSession()
{
	delete session;
	session = NULL;
}

