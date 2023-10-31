/* C:B**************************************************************************
This software is Copyright 2014-2017 Bright Plaza Inc. <drivetrust@drivetrust.com>
This software is Copyright 2017 Spectra Logic Corporation

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
#pragma once
class DtaCommand;
class DtaSession;

#include "os.h"
#include "DtaOptions.h"
#include "DtaDev.h"
#include "DtaDevOS.h"
#include "DtaStructures.h"
#include "DtaLexicon.h"
#include "DtaResponse.h"   // wouldn't take class
#include <vector>

using namespace std;
/** Device Class represents a disk device, conforming to the TCG Enterprise standard
*/

class DtaDevEnterprise : public DtaDevOS {
public:
        /** Constructor using an OS specific device descriptor.
         * @param devref reference to device is OS specific lexicon
         *  */
	DtaDevEnterprise(const char * devref);
         /** Default destructor, does nothing*/
	~DtaDevEnterprise();
        /** Inform TPer of the communication propertied I wiah to use and
         * receive the TPer maximum values
         */
	uint8_t properties();
         /** Send a command to the device and wait for the response
         * @param cmd the DtaCommand object containg the command
         * @param response the DtaResonse object containing the response
         * @param protocol The security protocol number to use for the command
         */
	uint8_t exec(const DtaCommand* cmd, DtaResponse& resp, const uint16_t ComID, const uint8_t protocol = 0x01);
         /** return the communications ID to be used for sessions to this device */
	uint16_t comID();
        /** Change the SID password from it's MSID default
         * @param newpassword  new password for SID
         */
	uint8_t takeOwnership(const char* newpassword);
        /** retrieve the MSID password */
	uint8_t printDefaultPassword();
         /** Set the SID password.
         * Requires special handling because password is not always hashed.
         * @param oldpassword  current SID password
         * @param newpassword  value password is to be changed to
         * @param hasholdpwd  is the old password to be hashed before being added to the bytestream
         * @param hashnewpwd  is the new password to be hashed before being added to the bytestream
         */
	uint8_t setSIDPassword(const char* oldpassword, const char* newpassword,
                           const uint8_t hasholdpwd = 1, const uint8_t hashnewpwd = 1);
    /** dummy code not implemented in the enterprise SSC */
	uint8_t activateLockingSP(const char* password, const uint32_t dsCount = 0,
                              const uint32_t dsSizes[] = NULL);
	/** dummy code not implemented in the enterprise SSC*/
	uint8_t activateLockingSP_SUM(const std::vector<uint32_t>& ranges, const uint32_t policy,
				      const char* password, const uint32_t dsCount = 0,
				      const uint32_t dsSizes[] = NULL);
	/** dummy code not implemented in the enterprise SSC*/
	uint8_t reactivateLockingSP_SUM(const char* authority, const char* password,
                                        const std::vector<uint32_t>& ranges, const uint32_t policy,
                                        const uint32_t dsCount = 0, const uint32_t dsSizes[] = NULL);
	/** dummy code not implemented in the enterprise SSC*/
	uint8_t eraseLockingRange_SUM(const char* authority, const uint8_t lockingrange,
				      const char* password);
	/** dummy code not implemented in the enterprise SSC */
	uint8_t lockLockingRange_SUM(const char* authority, const char* password,
				     const uint8_t lockingrange);
	/** dummy code not implemented in the enterprise SSC */
	uint8_t setFeatureLocking(const char* authority, const char* password,
				  const uint8_t column, const uint8_t value);
        /** dummy code not implemented in the enterprise SSC*/
	uint8_t revertSP(const char* sp, const char* authority, const char* password, const uint8_t keep = 0);
        /** Enable a Bandmaster Not functional */
	uint8_t enableUser(const char* sp, const char* authority, const char* password, const char* userid,
                       const OPAL_TOKEN status = OPAL_TOKEN::OPAL_TRUE);
         /** Primitive to set the MBRDone flag.
         * @param state 0 or 1
         * @param Admin1Password Locking SP authority with access to flag
         */
	uint8_t setMBRDone(const uint8_t state, const char* Admin1Password);
        /** Primitive to set the MBREnable flag.
         * @param state 0 or 1
         * @param Admin1Password Locking SP authority with access to flag
         */
	uint8_t setMBREnable(const uint8_t state, const char* Admin1Password);

        /** Set the password of a locking SP user.
         * @param sp security protocol to access
         * @param authority ignored in Enterprise
         * @param password  current password
         * @param userid the userid whose password is to be changed
         * @param newpassword  value password is to be changed to
         */
	uint8_t setPassword(const char* sp, const char* authority, const char *password, const char* userid,
                        const char *newpassword);
	/** dummy code not implemented in the enterprise SSC*/
	uint8_t setNewPassword_SUM(const char* password, const char* userid, const char* newpassword);
	uint8_t setLockingRange(const uint8_t lockingrange, const uint8_t lockingstate,
                            const char* authority, const char* password);
	/** dummy code not implemented in the enterprise SSC*/
	uint8_t setLockingRange_SUM(const uint8_t lockingrange, const uint8_t lockingstate,
                                const char* password);
	/** Setup a locking range.  Initialize a locking range, set it's start
	*  LBA and length, initialize it as unlocked with locking disabled.
	*  @param lockingrange The Locking Range to be setup
	*  @param start  Starting LBA
	*  @param length Number of blocks
	*  @param authority authority to use for the session
	*  @param password Password of the authority
	*/
	uint8_t setupLockingRange(const uint8_t lockingrange, const uint64_t start,
                              const uint64_t length, const char* authority, const char* password);
	/** dummy code not implemented in the enterprise SSC*/
	uint8_t setupLockingRange_SUM(const uint8_t lockingrange, const uint64_t start,
                                  const uint64_t length, const char* password);
	/** List status of locking ranges.
	* @param authority authority to use for the session
    * @param password Password of the authority 
    * @param rangeid index to the locking range row, -1 for all
	*/
	uint8_t listLockingRanges(const char* authority, const char* password, const int16_t rangeid);
	/** Change the active state of a locking range
	* @param lockingrange The number of the locking range (0 = global)
	* @param enabled  enable (true) or disable (false) the lockingrange
	* @param authority authority to use for the session
	* @param password Password of the authority
	*/
	uint8_t configureLockingRange(const uint8_t lockingrange, const uint8_t enabled,
                                  const char* authority, const char* password);
	/** dummy code not implemented in the enterprise SSC*/
    uint8_t configureLockingRange_SUM(const uint8_t lockingrange, const OPAL_LOCKINGSTATE enabled,
                                      const char* password);
	/** Generate a new encryption key for a locking range.
	* @param lockingrange locking range number
	* @param authority authority to use for the session
	* @param password Password of the authority
	*/
	uint8_t rekeyLockingRange(const uint8_t lockingrange, const char* authority, const char* password);
	uint8_t setBandsEnabled(const int16_t lockingrange, const char* password);
        /** Reset the TPER to its factory condition
         * ERASES ALL DATA!
         * @param authority selects the authority to use in the session
         * @param password password of authority (SID or PSID)
         * @param AdminSP set to 1 to use AdminSP instead of This for invokingID
         */
	uint8_t revertTPer(const char* authority, const char* password, const uint8_t AdminSP = 0);
	    /** Erase a locking range
	    * @param lockingrange The number of the locking range (0 = global)
	    * @param password Password of administrative authority for locking range
	    */
	uint8_t eraseLockingRange(const uint8_t lockingrange, const char* password);
       /** Loads a disk image file to the shadow MBR table.
         * @param password the password for the administrative authority with access to the table
         * @param filename the filename of the disk image
         */
	uint8_t loadPBA(const char* password, const char* filename);
         /** User command to prepare the device for management by sedutil.
         * Specific to the SSC that the device supports
         * @param password the password that is to be assigned to the SSC master entities
         */
	uint8_t initialSetup(const char* password);
	/** dummy code not implemented in the enterprise SSC*/
	uint8_t setup_SUM(const uint8_t lockingrange, const uint64_t start, const uint64_t length,
                      const char* Admin1Password, const char* password);
        /** Displays the identify and discovery 0 information */
	void puke();
         /** Dumps an object for diagnostic purposes
         * @param sp index into the OPALUID table for the SP the object is in
         * @param auth the authority to use for the dump
         * @param pass the password for the authority
         * @param objID the UID of the object to dump
         *  */
	uint8_t objDump(const char* sp, const char* auth, const char* pass, const char* objID);
         /** Issue any command to the drive for diagnostic purposes
         * @param sp index into the OPALUID table for the SP the object is in
         * @param hexauth the authority to use for the dump
         * @param pass the password for the authority
         * @param hexinvokingUID caller of the method
         * @param hexmethod the method to call
         * @param hexparms  the parameter list for the command
         *
         */
	uint8_t rawCmd(const char* sp, const char* hexauth, const char* pass,
                   const char* hexinvokingUID, const char* hexmethod, const char* hexparms);

	// virtual methods from DtaDev class
	uint8_t assign(const char* authority, const char* password, const uint32_t ns,
                   const uint64_t start = 0, const uint64_t length = 0, const uint32_t sum = 0);
	uint8_t deassign(const char* authority, const char* password, const uint8_t lockingrange,
                     const bool keep);
    uint8_t printTables(const char* sp, const char* password, const uint8_t level);
	uint8_t readMBR(const char* password, const uint32_t offset, const uint32_t count);
	uint8_t loadDataStore(const char* password, const uint8_t table, const uint32_t offset,
                          const uint32_t count, const char* filename);
	uint8_t readDataStore(const char* password, const uint8_t table, const uint32_t offset,
                          const uint32_t count);
    uint8_t enableTperReset(const char* password, const uint8_t options);
    uint8_t clearDoneOnReset(const char* authority, const char* password, const uint8_t options);

    uint8_t getACE(const char* sp, const char* auth, const char* password, const uint32_t halfRow);
    uint8_t setACE(const char* sp, const char* auth, const char* password, const uint32_t halfRow,
                   const char* expression);
    uint8_t getRandom(const char* sp, const char* authority, const char* password, const uint32_t size);

protected:
	uint8_t getDefaultPassword();
private:
    uint8_t getMaxRanges(const char* password, uint16_t *maxRanges);
    uint8_t getMaxRangesOpal(const char* password, uint16_t *maxRanges);
        /** set a single column in an object table
         * @param table the UID of the table
         * @param name the column name to be set
         * @param value data to be stored the the column
         */
	uint8_t setTable(const std::vector<uint8_t>& table, const char* name,
                     const std::vector<uint8_t>& value);
        /** set a single column in a table
         * @param table the UID of the table
         * @param name the column name to be set
         * @param value data to be stored the the column
         */
	uint8_t setTable(const std::vector<uint8_t>& table, const char* name,
                     const OPAL_TOKEN value);

        /** retrieve a single row from a table
         * @param table the UID of the table
         * @param startcol the starting column of data requested
         * @param endcol the ending column of the data requested
         */
	uint8_t getTable(const std::vector<uint8_t>& table, const char* startcol, const char* endcol);
        /** Change the passwords for the enabled Bandmasters and the Erasemaster
         * from the MSID default.
         * @param defaultPassword the MSID password
         * @param newPassword the nesw password to be set
         *  */
	uint8_t initLSPUsers(const char* defaultPassword, const char* newPassword);
};
