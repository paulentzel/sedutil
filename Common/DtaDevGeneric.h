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
#pragma once
class DtaCommand;
class DtaSession;
#include "os.h"
#include "DtaDev.h"
#include "DtaDevOS.h"
#include "DtaStructures.h"

#include <vector>

using namespace std;
/** Device Class representing an unknown type of disk device.
 * This device is used in determining if a disk supports a TCG Storage SSC.
 * Most of the functions in this class are implemented to return an error as
 * it is not known if the device supports a SSC
 *
*/
class DtaDevGeneric : public DtaDevOS {
public:
    /** Constructor using an OS specific device descriptor.
     * @param devref reference to device is OS specific lexicon
     *  */
    DtaDevGeneric(const char * devref);
    /** Default constructor */
	~DtaDevGeneric();
        /** OS specific initialization.
         * This function should perform the necessary authority and environment checking
         * to allow proper functioning of the program, open the device, perform an ATA
         * identify, add the fields from the identify response to the disk info structure
         * and if the device is an ATA device perform a call to Discovery0() to complete
         * the disk_info structure
         * @param devref character representation of the device is standard OS lexicon
         */
	 void init(const char * devref) ;
	/* sedutil.cpp */
         /** User command to prepare the device for management by sedutil.
         * Specific to the SSC that the device supports
         * @param password the password that is to be assigned to the SSC master entities
         */
	 uint8_t initialSetup(const char* password) ;
	/** User command to prepare the drive for Single User Mode and rekey a SUM locking range.
         * @param lockingrange locking range number to enable
         * @param start LBA to start locking range
         * @param length length (in blocks) for locking range
         * @param Admin1Password admin1 password for TPer
         * @param password User password to set for locking range
         */
         uint8_t setup_SUM(const uint8_t lockingrange, const uint64_t start, const uint64_t length,
                           const char* Admin1Password, const char* password);
          /** Set the SID password.
         * Requires special handling because password is not always hashed.
         * @param oldpassword  current SID password
         * @param newpassword  value password is to be changed to
         * @param hasholdpwd  is the old password to be hashed before being added to the bytestream
         * @param hashnewpwd  is the new password to be hashed before being added to the bytestream
         */
	 uint8_t setSIDPassword(const char* oldpassword, const char* newpassword,
                            const uint8_t hasholdpwd = 1, const uint8_t hashnewpwd = 1) ;
         /** Set the password of a locking SP user.
         * @param sp security protocol to access
         * @param authority authority to use for the session
         * @param password  current password
         * @param userid the userid whose password is to be changed
         * @param newpassword  value password is to be changed to
         */
	 uint8_t setPassword(const char* sp, const char* authority, const char* password, const char* userid,
                         const char* newpassword);
	 /** Set the password of a locking SP user in Single User Mode.
         * @param password  current user password
         * @param userid the userid whose password is to be changed
         * @param newpassword  value password is to be changed to
         */
	 uint8_t setNewPassword_SUM(const char* password, const char* userid, const char* newpassword);
          /** Loads a disk image file to the shadow MBR table.
         * @param password the password for the administrative authority with access to the table
         * @param filename the filename of the disk image
         */
	 uint8_t loadPBA(const char* password, const char* filename) ;
         /** Change the locking state of a locking range
         * @param lockingrange The number of the locking range (0 = global)
         * @param lockingstate  the locking state to set
         * @param authority authority to use for the session
         * @param password Password of authority
         */
	 uint8_t setLockingRange(const uint8_t lockingrange, const uint8_t lockingstate,
                             const char* authority, const char* Admin1Password) ;
	 /** Change the locking state of a locking range in Single User Mode
         * @param lockingrange The number of the locking range (0 = global)
         * @param lockingstate  the locking state to set
         * @param password password of user authority for the locking range
         */
	 uint8_t setLockingRange_SUM(const uint8_t lockingrange, const uint8_t lockingstate,
                                 const char* password);
         /** Change the active state of a locking range
         * @param lockingrange The number of the locking range (0 = global)
         * @param enabled  enable (true) or disable (false) the lockingrange
         * @param authority authority to use for the session
         * @param password password of administrative authority for locking range
         */
	 uint8_t configureLockingRange(const uint8_t lockingrange, const uint8_t enabled,
                                   const char* authority, const char* password);
     uint8_t configureLockingRange_SUM(const uint8_t lockingrange, const OPAL_LOCKINGSTATE enabled,
                                       const char* password);

	 /** Setup a locking range.  Initialize a locking range, set it's start
	 *  LBA and length, initialize it as unlocked with locking disabled.
	 *  @param lockingrange The Locking Range to be setup
	 *  @param start  Starting LBA
	 *  @param length Number of blocks
	 *  @param authority authority to use for the session
	 *  @param password Password of authority
	 */
	 uint8_t setupLockingRange(const uint8_t lockingrange, const uint64_t start,
                               const uint64_t length, const char* authority, const char* password);
	 /** Setup a locking range in Single User Mode.  Initialize a locking range,
	 *  set it's start LBA and length, initialize it as unlocked with locking enabled.
         *  @param lockingrange The Locking Range to be setup
         *  @param start  Starting LBA
         *  @param length Number of blocks
         *  @param password Password of administrator
         */
	 uint8_t setupLockingRange_SUM(const uint8_t lockingrange, const uint64_t start,
                                   const uint64_t length, const char* password);
         /** Primitive to set the MBRDone flag.
         * @param state 0 or 1
         * @param Admin1Password Locking SP authority with access to flag
         */
	 /** List status of locking ranges.
	 * @param authority authority to use for the session
     * @param password Password of authority 
     * @param locking range row index, -1 for all 
	 */
	 uint8_t listLockingRanges(const char* authority, const char* password, const int16_t rangeid);
	 /** Generate a new encryption key for a locking range.
	 * @param lockingrange locking range number
	 * @param authority authority to use for the session
	 * @param password password of the locking administrative authority
	 */
	 uint8_t rekeyLockingRange(const uint8_t lockingrange, const char* authority, const char* password);
	 /** Enable bands using MSID.
	 * @param lockingrange locking range number
	 */
	 uint8_t setBandsEnabled(const int16_t rangeid, const char* password);
	 uint8_t setMBRDone(const uint8_t state, const char* Admin1Password);
         /** Primitive to set the MBREnable flag.
         * @param state 0 or 1
         * @param Admin1Password Locking SP authority with access to flag
         */
	 uint8_t setMBREnable(const uint8_t state, const char* Admin1Password);
         /** enable a locking sp user.
         * @param sp security protocol to access
         * @param authority authority to use for the session
         * @param password password of locking sp authority
         * @param userid  the user to be enabled
         * @param status enable/disable
         */
	 uint8_t enableUser(const char* sp, const char* authority, const char* password, const char* userid,
                        const OPAL_TOKEN status = OPAL_TOKEN::OPAL_TRUE);
          /** Enable locking on the device
         * @param password password of the admin sp SID authority
         */
	 uint8_t activateLockingSP(const char* password, const uint32_t dsCount = 0,
                               const uint32_t dsSizes[] = NULL);
        /** Change state of the Locking SP to active in Single User Mode.
         * Enables locking in Single User Mode
		 * @param lockingrange  list of locking range numbers to activate in SUM (-1 = all)
		 * @param policy  the RangeStartRangeLengthPolicy (0 = user, 1 = admins)
		 * @param password  current SID password
		 * @param dsCount  Number of additional DataStore tables to create
		 * @param dsSizes  Sizes of the additional DataStore tables
         */
	uint8_t activateLockingSP_SUM(const std::vector<uint32_t>& ranges, const uint32_t policy,
	                              const char* password, const uint32_t dsCount = 0,
	                              const uint32_t dsSizes[] = NULL);
	/** Reactivate locking on the device in Single User Mode
	 * @param authority selects the authority to use in the session 
	 * @param password  current SID password
	 * @param lockingrange  list of locking range numbers to activate in SUM (-1 = all, -2 = none)
	 * @param policy  the RangeStartRangeLengthPolicy (0 = user, 1 = admins)
	 * @param dsCount  Number of additional DataStore tables to create
	 * @param dsSizes  Sizes of the additional DataStore tables
	*/ 
	uint8_t reactivateLockingSP_SUM(const char* authority, const char* password,
                                    const std::vector<uint32_t>& ranges, const uint32_t policy,
                                    const uint32_t dsCount = 0, const uint32_t dsSizes[] = NULL);
	/** Erase a Single User Mode locking range by calling the drive's erase method
         * @param authority selects the authority to use in the session 
         * @param lockingrange The Locking Range to erase
         * @param password The administrator password for the drive
         */
        uint8_t eraseLockingRange_SUM(const char* authority, const uint8_t lockingrange,
                                      const char* password);
	/** Lock a Single User Mode locking range by calling the drive's Lock method
	 * @param authority selects the authority to use in the session 
	 * @param password The password for the selected authority
	 * @param lockingrange The Locking Range to Lock 
	 */
    uint8_t lockLockingRange_SUM(const char* authority, const char* password,
                                 const uint8_t lockingrange);
	/** Set a value in the VU FeatureLocking table
	 * @param authority selects the authority to use in the session 
	 * @param password The password for the selected authority
	 * @param column selects the column to update (0 will just read the table and dump)
	 *               values)
	 * @param value The value to write to the selected column
	 */
     uint8_t setFeatureLocking(const char* authority, const char* password,
                               const uint8_t column, const uint8_t value);
        /** Change the SID password from it's MSID default
         * @param newpassword  new password for SID and locking SP admins
         */
	 uint8_t takeOwnership(const char* newpassword) ;
         /** Reset the Locking SP to its factory default condition
         * ERASES ALL DATA!
         * @param password of Administrative user
         * @param keep true false for noerase function NOT WWORKING
         */
	 uint8_t revertSP(const char* sp, const char* authority, const char* password, const uint8_t keep ) ;
         /** Reset the TPER to its factory condition
         * ERASES ALL DATA!
         * @param authority selects the authority to use in the session
         * @param password password of authority (SID or PSID)
         * @param AdminSP set to 1 to use AdminSP instead of This for invokingID
         */
	 uint8_t revertTPer(const char* authority, const char* password, const uint8_t AdminSP);
	    /** Erase a locking range
	    * @param lockingrange The number of the locking range (0 = global)
	    * @param password Password of administrative authority for locking range
	    */
	 uint8_t eraseLockingRange(const uint8_t lockingrange, const char* password);
         /** Dumps an object for diagnostic purposes
         * @param sp index into the OPALUID table for the SP the object is in
         * @param auth the authority to use for the dump
         * @param pass the password for the authority
         * @param objID the UID of the object to dump
         */
	 uint8_t objDump(const char* sp, const char* auth, const char* pass,
                     const char* objID);
         /** Issue any command to the drive for diagnostic purposes
         * @param sp index into the OPALUID table for the SP the object is in
         * @param auth the authority to use for the dump
         * @param pass the password for the authority
         * @param invoker caller of the method
         * @param method the method to call
         * @param plist  the parameter list for the command
         *
         */
	 uint8_t rawCmd(const char* sp, const char* auth, const char* pass,
                    const char* invoker, const char* method, const char* plist) ;
	/** Read MSID
	 */
	uint8_t printDefaultPassword();
    /** print table contents.
     */
    uint8_t printTables(const char* sp, const char* password, const uint8_t level);
	/* DtaSession.cpp 	*/
        /** Send a command to the device and wait for the response
         * @param cmd the MswdCommand object containg the command
         * @param response the DtaResonse object containing the response
         * @param protocol The security protocol number to use for the command
         */
	 uint8_t exec(const DtaCommand* cmd, DtaResponse& resp, const uint16_t ComID, const uint8_t protocol = 1) ;
         /** return the communications ID to be used for sessions to this device */
	 uint16_t comID() ;

     // virtual methods from DtaDev class
     uint8_t assign(const char* authority, const char* password, const uint32_t ns,
                    const uint64_t start = 0, const uint64_t length = 0, const uint32_t sum = 0);
     uint8_t deassign(const char* authority, const char* password, const uint8_t lockingrange,
                      const bool keep);
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
};
