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

#include "DtaDev.h"
#include "DtaDevOS.h"
#include "DtaStructures.h"
#include "DtaLexicon.h"
#include "DtaResponse.h"   // wouldn't take class
#include <vector>
#include <map>

using namespace std;

typedef std::map<int, std::string> columnMap_t;

typedef struct _tableDesc
{
    const char* name;
    const char* notes;
    uint8_t     uid[8];
    uint8_t     defaultRow[8];
    uint8_t     kind;
    uint8_t     skip;
    uint32_t    columnCount;
    columnMap_t columns;
} tableDesc_t;

typedef std::map<uint32_t, std::string> rowMap_t;
typedef std::vector<rowMap_t> tableRows_t;

/** Common code for OPAL SSCs.
 * most of the code that works for OPAL 2.0 also works for OPAL 1.0
 * that common code is implemented in this class
 */
class DtaDevOpal : public DtaDevOS {
public:
    /** Default Constructor */
	DtaDevOpal();
        /** default Destructor */
	~DtaDevOpal();
        /** OS specific initialization.
         * This function should perform the necessary authority and environment checking
         * to allow proper functioning of the program, open the device, perform an ATA
         * identify, add the fields from the identify response to the disk info structure
         * and if the device is an ATA device perform a call to Discovery0() to complete
         * the disk_info structure
         * @param devref character representation of the device is standard OS lexicon
         */
	void init(const char * devref);
        /** Notify the device of the host properties and receive the
         * properties of the device as a reply */
	uint8_t properties();
         /** Send a command to the device and wait for the response
         * @param cmd the MswdCommand object containg the command
         * @param response the DtaResonse object containing the response
         * @param protocol The security protocol number to use for the command
         */
	uint8_t exec(const DtaCommand* cmd, DtaResponse& resp, const uint16_t ComID, const uint8_t protocol = 0x01);
         /** return the communications ID to be used for sessions to this device */
	virtual uint16_t comID() = 0;
        /** Change the SID password from it's MSID default
         * @param newpassword  new password for SID
         */
	uint8_t takeOwnership(const char* newpassword);
        /** retrieve the MSID password */
	uint8_t printDefaultPassword();
	    /** Print the supported tables */
	uint8_t printTables(const char* sp, const char* password, const uint8_t level);
        /** retrieve a single row from a table
         * @param table the UID of the table
         * @param startcol the starting column of data requested
         * @param endcol the ending column of the data requested
         */
	uint8_t getTable(const std::vector<uint8_t>& table, const uint32_t startcol, const uint32_t endcol);
         /** Set the SID password.
         * Requires special handling because password is not always hashed.
         * @param oldpassword  current SID password
         * @param newpassword  value password is to be changed to
         * @param hasholdpwd  is the old password to be hashed before being added to the bytestream
         * @param hashnewpwd  is the new password to be hashed before being added to the bytestream
         */
	uint8_t setSIDPassword(const char* oldpassword, const char* newpassword,
						   const uint8_t hasholdpwd = 1, const uint8_t hashnewpwd = 1);
         /** set a single column in an object table
         * @param table the UID of the table
         * @param name the column name to be set
		 * @param value data to be stored the the column
         */
	uint8_t setTable(const std::vector<uint8_t>& table, const OPAL_TOKEN name,
					 const std::vector<uint8_t>& value);
         /** set a single column in an object table
         * @param table the UID of the table
         * @param name the column name to be set
         * @param value data to be stored the the column
         */
	uint8_t setTable(const std::vector<uint8_t>& table, const OPAL_TOKEN name,
					 const OPAL_TOKEN value);
        /** Change state of the Locking SP to active.
         * Enables locking
         * @param password  current SID password
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

        /** Erase a Single User Mode locking range by calling the drive's erase method
          * @param authority selects the authority to use in the session 
          * @param lockingrange The Locking Range to erase
          * @param password The administrator password for the drive
          */
        uint8_t eraseLockingRange_SUM(const char* authority, const uint8_t lockingrange,
                                      const char* password);
        /** Restore the state of the Locking SP to factory defaults.
         * Enables locking
         * @param password  current SID password
         * @param keep boolean keep the data (NOT FUNCTIONAL)
         */
	uint8_t revertSP(const char* sp, const char* authority, const char* password, const uint8_t keep = 0);
         /** get the UID or CPIN ID of a user from their character name
          * @param sp UID enum of the sp
          * @param userid  Character user name
          * @param column UID or CPIN to be returned
          * @param userData The UIS or CPIN of the USER
          */
	uint8_t getAuth4User(const OPAL_UID sp, const char* userid, const uint8_t column, std::vector<uint8_t> &userData) const;
		/**  Enable a user in the Locking SP
         * @param sp security protocol to access
         * @param authority authority to use for the session
         * @param password password of locking sp authority
         * @param userid  the user to be enabled
         * @param status enable/disable
         */
	uint8_t enableUser(const char* sp, const char* authority, const char* password, const char* userid,
					   const OPAL_TOKEN status = OPAL_TOKEN::OPAL_TRUE);
        /** Primitive to set the MBRDone flag.
         * @param state 0 or 1
         * @param Admin1Password Locking SP authority with access to flag
		 * @param status true or false to enable/disable
         */
	uint8_t setMBRDone(const uint8_t state, const char* Admin1Password);
        /** Primitive to set the MBREnable flag.
         * @param state 0 or 1
         * @param Admin1Password Locking SP authority with access to flag
         */
	uint8_t setMBREnable(const uint8_t state, const char* Admin1Password);
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
        /** User command to manipulate the state of a locking range.
         * RW|RO|LK are the supported states @see OPAL_LOCKINGSTATE
         * @param lockingrange locking range number
         * @param lockingstate desired locking state (see above)
         * @param authority authority to use for the session
         * @param password password of the locking administrative authority
         */
	uint8_t setLockingRange(const uint8_t lockingrange, const uint8_t lockingstate,
							const char* authority, const char* password);

	/** Change the locking state of a locking range in Single User Mode
         * @param lockingrange The number of the locking range (0 = global)
         * @param lockingstate  the locking state to set
         * @param password password of user authority for the locking range
         */
	uint8_t setLockingRange_SUM(const uint8_t lockingrange, const uint8_t lockingstate,
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
	/** List status of locking ranges.
	*  @param authority authority to use for the session
	*  @param password Password of the authority
	*  @param rangeid range IS to list, or -1 for all 
	*/
	uint8_t listLockingRanges(const char* authority, const char* password, const int16_t rangeid);

        /** User command to enable/disable a locking range.
         * RW|RO|LK are the supported states @see OPAL_LOCKINGSTATE
         * @param lockingrange locking range number
         * @param enabled boolean true = enabled, false = disabled
         * @param authority authority to use for the session
         * @param password password of the locking administrative authority
         */
	uint8_t configureLockingRange(const uint8_t lockingrange, const uint8_t enabled,
								  const char* authority, const char* password);

	/** Change the active state of a locking range in single-user mode
	 * @param lockingrange The number of the locking range (0 = global)
	 * @param enabled OPAL_LOCKINGSTATE indicating the locking state to set
	 * @param password Password of administrative authority for locking range
	 */
	uint8_t configureLockingRange_SUM(const uint8_t lockingrange, const OPAL_LOCKINGSTATE enabled,
                                      const char* password);
	/** Generate a new encryption key for a locking range.
	* @param lockingrange locking range number
	* @param authority authority to use for the session
	* @param password password of the locking administrative authority
	*/
	uint8_t rekeyLockingRange(const uint8_t lockingrange, const char* authority, const char* password);
	/** Generate a new encryption key for a Single User Mode locking range.
        * @param LR locking range UID in vector format
	* @param UID user UID in vector format
        * @param password password of the UID authority
        */
	uint8_t rekeyLockingRange_SUM(const std::vector<uint8_t>& LR, const std::vector<uint8_t>& UID,
								  const char* password);
	/** Reset the TPER to its factory condition
         * ERASES ALL DATA!
         * @param password password of authority (SID or PSID)
         * @param PSID true or false is the authority the PSID
         *   */
	/** Enable bands using MSID.
	* @param lockingrange locking range number
	*/
	uint8_t setBandsEnabled(const int16_t rangeid, const char* password);
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
	/** User command to prepare the drive for Single User Mode and rekey a SUM locking range.
         * @param lockingrange locking range number to enable
         * @param start LBA to start locking range
         * @param length length (in blocks) for locking range
         * @param Admin1Password admin1 password for TPer
         * @param password User password to set for locking range
         */
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
	uint8_t rawCmd(const char* sp, const char*  auth, const char* pass,
				   const char* invoker, const char* method, const char* plist);

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

protected:
        /** Primitive to handle the setting of a value in the a table in locking sp.
         * @param table_uid UID of the table
         * @param name column to be altered
         * @param value the value to be set
         * @param password password for the administrative authority
         * @param msg message to be displayed upon successful update;
         */
	uint8_t setLockingSPvalue(const OPAL_UID table_uid, const OPAL_TOKEN name, const OPAL_TOKEN value,
                              const char* password, const char* msg = "New Value Set");

	uint8_t getDefaultPassword();
	typedef struct lrStatus
	{
		uint8_t command_status; //return code of locking range query command
		uint8_t lockingrange_num; //which locking range is this
		uint64_t start;
		uint64_t size;
		bool RLKEna;
		bool WLKEna;
		bool RLocked;
		bool WLocked;
	}lrStatus_t;
	/** Get info programatically for single locking range
	 *  @param lockingrange locking range number to check
	 *  @param password Admin1 Password for TPer
	 */
	lrStatus_t getLockingRange_status(const uint8_t lockingrange, const char* password);

    uint8_t getByteTable(const std::vector<uint8_t>& tableUID, const uint32_t row, 
                         const uint32_t count, uint8_t* buffer);

	uint8_t verifyPassword(const OPAL_UID sp, const OPAL_UID auth, const std::string& pw);
	uint8_t nextTable(const std::vector<uint8_t>& table);
	uint8_t nextTableRow(const OPAL_UID sp, const OPAL_UID auth, const std::string& pw,
						 const std::vector<uint8_t>& uid);
    uint8_t getTable(const vector<uint8_t>& table);
	uint8_t getTableRow(const vector<uint8_t>& uid, const tableDesc_t* tableDesc,
						const OPAL_UID sp, const OPAL_UID auth, const std::string& password,
						rowMap_t& rowMap, const uint8_t level);
	uint8_t getACLCmd(const std::vector<uint8_t>& object,
		              const std::vector<uint8_t>& method);
	uint8_t getACL(const std::vector<uint8_t>& object,
				   const std::vector<uint8_t>& method,
				   std::string& str, const uint8_t level);
    uint8_t getACLRow(const std::vector<uint8_t>& object,
		              const std::vector<std::vector<uint8_t>>& methods,
				      const OPAL_UID sp, const OPAL_UID auth, const std::string& password,
					  tableRows_t& output, const uint8_t level);
	void printUID(const std::vector<uint8_t>& uid);
	void printUID(const uint8_t* uid);
	void printUID(const std::vector<uint8_t>& uid, std::string& str);
	void printBytes(const uint8_t* uid, const int length, char* str);
	uint8_t printTablesForSP(const char* spStr, const OPAL_UID sp, const OPAL_UID auth,
							 const std::string& pw, const uint8_t level);
	void deleteSession();

private:
	uint8_t getTableWriteGranularity(std::vector<uint8_t>& tableRowUID, uint32_t* gran);
};
