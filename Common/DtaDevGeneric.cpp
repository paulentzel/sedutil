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
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4100)
#endif

#include "os.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include<iomanip>
#include "DtaOptions.h"
#include "DtaDevGeneric.h"
#include "DtaHashPwd.h"
#include "DtaEndianFixup.h"
#include "DtaStructures.h"
#include "DtaCommand.h"
#include "DtaResponse.h"
#include "DtaSession.h"
#include "DtaHexDump.h"

using namespace std;

/** Class representing a disk device, this class is intended to be used when
 * it is not yet known if the device is OPAL compliant
 */

#define voidNOCODE(name, ...) void DtaDevGeneric::name(##__VA_ARGS__) { \
LOG(E) << "Generic Device class does not support function " << #name << std::endl; \
}
#define uint8NOCODE(name, ...) uint8_t DtaDevGeneric::name(__VA_ARGS__) { \
LOG(E) << "Generic Device class does not support function " << #name << std::endl; \
return 0xff; \
}

DtaDevGeneric::DtaDevGeneric(const char * devref)
{
	DtaDevOS::init(devref);
}

DtaDevGeneric::~DtaDevGeneric()
{
}
void DtaDevGeneric::init(const char * devref)
{
}
uint8NOCODE(initialSetup, const char* password)
uint8NOCODE(configureLockingRange, const uint8_t lockingrange,
            const uint8_t enabled, const char* authority, const char* password)
uint8NOCODE(configureLockingRange_SUM, const uint8_t lockingrange, const OPAL_LOCKINGSTATE enabled,
            const char* password)
uint8NOCODE(revertSP, const char* sp, const char* authority, const char* password, const uint8_t keep)
uint8NOCODE(setup_SUM, const uint8_t lockingrange, const uint64_t start, const uint64_t length,
            const char* Admin1Password, const char* password)
uint8NOCODE(setPassword, const char* sp, const char* authority, const char* password, const char* userid,
            const char* newpassword)
uint8NOCODE(setNewPassword_SUM, const char* password, const char* userid, const char* newpassword)
uint8NOCODE(setMBREnable, const uint8_t mbrstate, const char* Admin1Password)
uint8NOCODE(setMBRDone, const uint8_t mbrstate, const char* Admin1Password)
uint8NOCODE(setLockingRange, const uint8_t lockingrange, const uint8_t lockingstate,
            const char* authority, const char* Admin1Password)
uint8NOCODE(setLockingRange_SUM, const uint8_t lockingrange, const uint8_t lockingstate,
            const char* password)
uint8NOCODE(setupLockingRange, const uint8_t lockingrange, const uint64_t start,
            const uint64_t length, const char* authority, const char* password)
uint8NOCODE(listLockingRanges, const char* authority, const char* password, const int16_t rangeid)
uint8NOCODE(setupLockingRange_SUM, const uint8_t lockingrange, const uint64_t start,
            const uint64_t length, const char* password)
uint8NOCODE(rekeyLockingRange, const uint8_t lockingrange, const char* authority, const char* password)
uint8NOCODE(setBandsEnabled, const int16_t lockingrange, const char* password)
uint8NOCODE(enableUser, const char* sp, const char* authority, const char* password, const char* userid,
            const OPAL_TOKEN status)
uint8NOCODE(revertTPer, const char* authority, const char* password, const uint8_t AdminSP)
uint8NOCODE(eraseLockingRange, const uint8_t lockingrange, const char* password)
uint8NOCODE(printDefaultPassword);
uint8NOCODE(loadPBA, const char* password, const char* filename)
uint8NOCODE(activateLockingSP, const char* password, const uint32_t dsCount, const uint32_t dsSizes[])
uint8NOCODE(activateLockingSP_SUM, const std::vector<uint32_t>& ranges, const uint32_t policy, const char* password,
            const uint32_t dsCount, const uint32_t dsSizes[])
uint8NOCODE(reactivateLockingSP_SUM, const char* authority,  const char* password,const std::vector<uint32_t>& ranges,
            const uint32_t policy, const uint32_t dsCount, const uint32_t dsSizes[])
uint8NOCODE(eraseLockingRange_SUM, const char* authority, const uint8_t lockingrange, const char* password)
uint8NOCODE(lockLockingRange_SUM, const char* authority, const char* password, const uint8_t lockingrange)
uint8NOCODE(setFeatureLocking, const char* authority, const char* password, const uint8_t column, const uint8_t value)
uint8NOCODE(takeOwnership, const char* newpassword)
uint8NOCODE(setSIDPassword, const char* oldpassword, const char* newpassword,
            const uint8_t hasholdpwd, const uint8_t hashnewpwd)
uint8NOCODE(printTables, const char* sp, const char* password, const uint8_t level)
uint8NOCODE(assign, const char* authority, const char* password, const uint32_t ns, const uint64_t start,
            const uint64_t length, const uint32_t sum)
uint8NOCODE(deassign, const char* authority, const char* password, const uint8_t lockingrange, const bool keep)
uint8NOCODE(readMBR, const char* password, const uint32_t offset, const uint32_t count)
uint8NOCODE(loadDataStore, const char* password, const uint8_t table, const uint32_t offset,
            const uint32_t count, const char* filename)
uint8NOCODE(readDataStore, const char* password, const uint8_t table, const uint32_t offset, const uint32_t count)
uint8NOCODE(enableTperReset, const char* password, const uint8_t options)
uint8NOCODE(clearDoneOnReset, const char* authority, const char* password, const uint8_t options)
uint8NOCODE(getACE, const char* sp, const char* auth, const char* password, const uint32_t halfRow)
uint8NOCODE(setACE, const char* sp, const char* auth, const char* password, const uint32_t halfRow, const char* expression)
uint8NOCODE(getRandom, const char* sp, const char* auth, const char* password, const uint32_t size)

uint16_t DtaDevGeneric::comID()
{
	LOG(E) << "Generic Device class does not support function " << "comID" << std::endl;
		return 0xff;
}

uint8NOCODE(exec, const DtaCommand* cmd, DtaResponse& resp, const uint16_t ComID, const uint8_t protocol)
uint8NOCODE(objDump, const char* sp, const char* auth, const char* pass, const char* objID)
uint8NOCODE(rawCmd, const char* sp, const char* auth, const char* pass, const char* invoker,
            const char* method, const char* plist)
#ifdef _MSC_VER
#pragma warning(pop)
#endif
