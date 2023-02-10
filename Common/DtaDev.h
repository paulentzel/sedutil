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
#include "DtaStructures.h"
#include "DtaLexicon.h"
#include <vector>
#include "DtaOptions.h"
#include "DtaResponse.h"
#include <fstream>

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

class DtaCommand;
class DtaSession;

using namespace std;
/** Base class for a disk device.
 * This is a virtual base class defining the minimum functionality of device
 * object.  The methods defined here are called by other parts of the program
 * so must be present in all devices
 */
class DtaDev {
public:
	/** Default constructor, does nothing */
	DtaDev();
	/** Default destructor, does nothing*/
	virtual ~DtaDev();
	/** Does the device conform to the Ruby 1.0 SSC */
	uint8_t isRuby1() const;
	/** Does the device conform to the Pyrite 2.0 SSC */
	uint8_t isPyrite2() const;
	/** Does the device conform to the Pyrite 1.0 SSC */
	uint8_t isPyrite1() const;
	/** Does the device conform to the Opalite SSC */
	uint8_t isOpalite() const;
	/** Does the device conform to the OPAL 2.0 SSC */
	uint8_t isOpal2() const;
	/** Does the device conform to the OPAL 1.0 SSC */
	uint8_t isOpal1() const;
	/** Does the device conform to the OPAL Enterprise SSC */
	uint8_t isEprise() const;
	/** Does the device conform to ANY TCG storage SSC */
	uint8_t isAnySSC() const;
	/** Is the MBREnabled flag set */
	uint8_t MBREnabled() const;
	/** Is the MBRDone flag set */
	uint8_t MBRDone() const;
	/** Is the MBRAbsent flag set */
	uint8_t MBRAbsent() const;
	/** Is the Locked flag set */
	uint8_t Locked() const;
	/** Is the Locking SP enabled */
	uint8_t LockingEnabled() const;
	/** Is there an OS disk represented by this object */
	uint8_t isPresent() const;
	/** Returns the Firmware revision reported by the identify command */
	const char* getFirmwareRev() const;
	/** Returns the Model Number reported by the Identify command */
	const char* getModelNum() const;
	/** Returns the Serial Number reported by the Identify command */
	const char* getSerialNum() const;
	/* What type of disk attachment is used */
	DTA_DEVICE_TYPE getDevType() const;
	/** displays the information returned by the Discovery 0 reply */
	virtual void puke();

	/** Decode the Discovery 0 response. Scans the D0 response and creates a structure
	 * that can be queried later as required.This code also takes care of
	 * the endianess conversions either via a bitswap in the structure or executing
	 * a macro when the input buffer is read.
	 */
	void discovery0();

    void printSecurityCompliance();

    uint8_t dynamicComID(uint16_t* ComID, uint16_t* ComIDExtension);

    void tokenizeUID(vector<uint8_t> & v, const uint8_t value[8]);
    void tokenizeUID(vector<uint8_t> & v, const OPAL_UID uid);

	/*
	 * virtual methods required in the OS specific
	 * device class
	 */
	/** OS specific initialization.
	 * This function should perform the necessary authority and environment checking
	 * to allow proper functioning of the program, open the device, perform an ATA
	 * identify, add the fields from the identify response to the disk info structure
	 * and if the device is an ATA device perform a call to Discovery0() to complete
	 * the disk_info structure
	 * @param devref character representation of the device is standard OS lexicon
	 */
	virtual void init(const char * devref) = 0;
	/** OS specific method to send an ATA command to the device
	 * @param cmd ATA command to be sent to the device
	 * @param protocol security protocol to be used in the command
	 * @param comID communications ID to be used
	 * @param buffer input/output buffer
	 * @param bufferlen length of the input/output buffer
	 */
	virtual uint8_t sendCmd(ATACOMMAND cmd, uint8_t protocol, uint16_t comID,
		void * buffer, uint32_t bufferlen) = 0;
	/** OS specific command to Wait for specified number of milliseconds
	 * @param milliseconds  number of milliseconds to wait
	 */
	virtual void osmsSleep(uint32_t milliseconds) = 0;
	/** OS specific routine to send an ATA identify to the device */
	virtual void identify(OPAL_DiskInfo& disk_info) = 0;
	/** OS specific routine to get size of the device */
	virtual unsigned long long getSize() = 0;
	/*
	 * virtual functions required to be implemented
	 * because they are called by sedutil.cpp
	 */
	/** User command to prepare the device for management by sedutil.
	 * Specific to the SSC that the device supports
	 * @param password the password that is to be assigned to the SSC master entities
	 */
	virtual uint8_t initialSetup(const char* password) = 0;
	/** User command to prepare the drive for Single User Mode and rekey a SUM locking range.
	 * @param lockingrange locking range number to enable
	 * @param start LBA to start locking range
	 * @param length length (in blocks) for locking range
	 * @param Admin1Password admin1 password for TPer
	 * @param password User password to set for locking range
	 */
	virtual uint8_t setup_SUM(const uint8_t lockingrange, const uint64_t start, const uint64_t length,
                              const char* Admin1Password, const char* password) = 0;
	/** Set the SID password.
	 * Requires special handling because password is not always hashed.
	 * @param oldpassword  current SID password
	 * @param newpassword  value password is to be changed to
	 * @param hasholdpwd  is the old password to be hashed before being added to the bytestream
	 * @param hashnewpwd  is the new password to be hashed before being added to the bytestream
	 */
	virtual uint8_t setSIDPassword(const char* oldpassword, const char* newpassword,
                                   const uint8_t hasholdpwd = 1, const uint8_t hashnewpwd = 1) = 0;
    /** Set the password of a locking SP user.
     * @param sp security protocol to access
     * @param authority authority to use for the session
	 * @param password  current password
	 * @param userid the userid whose password is to be changed
	 * @param newpassword  value password is to be changed to
	 */
	virtual uint8_t setPassword(const char* sp, const char* authority, const char* password,
                                const char* userid, const char* newpassword) = 0;
	/** Set the password of a locking SP user in Single User Mode.
     * @param password  current user password
     * @param userid the userid whose password is to be changed
     * @param newpassword  value password is to be changed to
     */
	virtual uint8_t setNewPassword_SUM(const char* password, const char* userid, 
                                       const char* newpassword) = 0;
	/** Loads a disk image file to the shadow MBR table.
	 * @param password the password for the administrative authority with access to the table
	 * @param filename the filename of the disk image
	 */
	virtual uint8_t loadPBA(const char* password, const char* filename) = 0;
	/** Prints the contents of the MBR as read from the table
	 * @param password the password for the LockingSP Admin1 authority
	 * @param offset offset from row 0 to begin the Get operartion
	 * @param count number of bytes to get and print
	 */
	virtual uint8_t readMBR(const char* password, const uint32_t offset, const uint32_t count) = 0;
	/** Loads data from a disk file to the DataStore table.
     * @param password the password for the administrative authority with access to
     *                 the table
	 * @param offset offset from row 0 to beging the Set operation.
	 * @param count number of bytes to set.
	 * @param filename the filename of the disk image
	 */
	virtual uint8_t loadDataStore(const char* password, const uint8_t table, const uint32_t offset,
                                  const uint32_t count, const char* filename) = 0;
	/** Prints the contents of the DataStore as read from the table
	 * @param password the password for the LockingSP Admin1 authority
	 * @param offset offset from row 0 to begin the Get operartion
	 * @param count number of bytes to get and print
	 */
	virtual uint8_t readDataStore(const char* password, const uint8_t table, const uint32_t offset,
	                              const uint32_t count) = 0;
	/** Change the locking state of a locking range
	 * @param lockingrange The number of the locking range (0 = global)
	 * @param lockingstate  the locking state to set
	*  @param authority authority to use for the session
	*  @param password Password of authority
	 */
	virtual uint8_t setLockingRange(const uint8_t lockingrange, const uint8_t lockingstate,
                                    const char* authority, const char * Admin1Password) = 0;
	/** Change the locking state of a locking range in Single User Mode
         * @param lockingrange The number of the locking range (0 = global)
         * @param lockingstate  the locking state to set
         * @param password password of user authority for the locking range
         */
	virtual uint8_t setLockingRange_SUM(const uint8_t lockingrange, const uint8_t lockingstate,
                                        const char* password) = 0;
	/** Change the active state of a locking range
	 * @param lockingrange The number of the locking range (0 = global)
	 * @param enabled  enable (true) or disable (false) the lockingrange
	 * @param authority authority to use for the session
	 * @param password Password of authority
	 */
	virtual uint8_t configureLockingRange(const uint8_t lockingrange, const uint8_t enabled,
                                          const char* authority, const char* password) = 0;
	/** Change the active state of a locking range in single-user mode
	 * @param lockingrange The number of the locking range (0 = global)
	 * @param enabled OPAL_LOCKINGSTATE indicating the locking state to set
	 * @param password Password of Admin1
	 */
	virtual uint8_t configureLockingRange_SUM(const uint8_t lockingrange, const OPAL_LOCKINGSTATE enabled,
                                              const char* password) = 0;

	/** Setup a locking range.  Initialize a locking range, set it's start
	 *  LBA and length, initialize it as unlocked with locking disabled.
	 *  @param lockingrange The Locking Range to be setup
	 *  @param start  Starting LBA
	 *  @param length Number of blocks
	 *  @param authority authority to use for the session
	 *  @param password Password of authority
	 */
	virtual uint8_t setupLockingRange(const uint8_t lockingrange, const uint64_t start,
                                      const uint64_t length, const char* authority, const char* password) = 0;

	/** Setup a locking range in Single User Mode.  Initialize a locking range,
	 *  set it's start LBA and length, initialize it as unlocked with locking enabled.
         *  @param lockingrange The Locking Range to be setup
         *  @param start  Starting LBA
         *  @param length Number of blocks
         *  @param password Password of administrator
         */
	virtual uint8_t setupLockingRange_SUM(const uint8_t lockingrange, const uint64_t start,
                                          const uint64_t length, const char* password) = 0;
	/** List status of locking ranges.
	* @param authority authority to use for the session
    * @param password Password of the authority
    * @param rangeid ID of the locking range row, or -1 for all
	*/
	virtual uint8_t listLockingRanges(const char* authority, const char* password, const int16_t rangeid) = 0;

	/** Generate a new encryption key for a locking range.
	* @param lockingrange locking range number
	* @param authority authority to use for the session
	* @param password Password of authority
	*/
	virtual uint8_t rekeyLockingRange(const uint8_t lockingrange, const char* authority,
                                      const char* password) = 0;

	/** Enable bands using MSID.
	* @param lockingrange locking range number
	*/
	virtual uint8_t setBandsEnabled(const int16_t rangeid, const char* password) = 0;
	/** Primitive to set the MBRDone flag.
	 * @param state 0 or 1
	 * @param Admin1Password Locking SP authority with access to flag
	 */
	virtual uint8_t setMBRDone(const uint8_t state, const char* Admin1Password) = 0;
	/** Primitive to set the MBREnable flag.
	 * @param state 0 or 1
	 * @param Admin1Password Locking SP authority with access to flag
	 */
	virtual uint8_t setMBREnable(const uint8_t state, const char* Admin1Password) = 0;
    /** enable a user.
     * @param sp security protocol to access
     * @param authority authority to use for the session
	 * @param password password of locking sp authority
     * @param userid  the user to be enabled
     * @param status enable/disable
	 */
	virtual uint8_t enableUser(const char* sp, const char* authority, const char* password,
                               const char* userid, const OPAL_TOKEN status = OPAL_TOKEN::OPAL_TRUE) = 0;
	/** Enable locking on the device
	 * @param password password of the admin sp SID authority
	 */
	virtual uint8_t activateLockingSP(const char* password, const uint32_t dsCount = 0,
                                      const uint32_t dsSizes[] = NULL) = 0;
	/** Enable locking on the device in Single User Mode
	 * @param lockingrange  list of locking range numbers to activate in SUM (-1 = all)
	 * @param policy  the RangeStartRangeLengthPolicy (0 = user, 1 = admins)
	 * @param password  current SID password
	 * @param dsCount  Number of additional DataStore tables to create
	 * @param dsSizes  Sizes of the additional DataStore tables
	 */
	virtual uint8_t activateLockingSP_SUM(const std::vector<uint32_t>& ranges, const uint32_t policy,
					      const char* password, const uint32_t dsCount = 0,
                                              const uint32_t dsSizes[] = NULL) = 0;
	/** Reactivate locking on the device in Single User Mode
	 * @param authority selects the authority to use in the session
	 * @param password  current SID password
	 * @param lockingrange  list of locking range numbers to activate in SUM (-1 = all, -2 = none)
	 * @param policy  the RangeStartRangeLengthPolicy (0 = user, 1 = admins)
	 * @param dsCount  Number of additional DataStore tables to create
	 * @param dsSizes  Sizes of the additional DataStore tables
	*/ 
	virtual uint8_t reactivateLockingSP_SUM(const char* authority, const char* password,
                                                const std::vector<uint32_t>& ranges, const uint32_t policy,
                                                const uint32_t dsCount = 0,
                                                const uint32_t dsSizes[] = NULL) = 0;
	/** Erase a Single User Mode locking range by calling the drive's erase method
	 * @param authority selects the authority to use in the session
	 * @param lockingrange The Locking Range to erase
	 * @param password The administrator password for the drive
	 */
	virtual uint8_t eraseLockingRange_SUM(const char* authority, const uint8_t lockingrange,
					      const char* password) = 0;

	/** Lock a Single User Mode locking range by calling the drive's Lock method
	 * @param authority selects the authority to use in the session 
	 * @param password The password for the selected authority
	 * @param lockingrange The Locking Range to Lock 
	 */
	virtual uint8_t lockLockingRange_SUM(const char* authority, const char* password,
					     const uint8_t lockingrange) = 0;

	/** Set a value in the VU FeatureLocking table
	 * @param authority selects the authority to use in the session 
	 * @param password The password for the selected authority
	 * @param column selects the column to update (0 will just read the table and dump)
	 *      	 values)
	 * @param value The value to write to the selected column
	 */
	virtual uint8_t setFeatureLocking(const char* authority, const char* password,
					  const uint8_t column, const uint8_t value) = 0;

	/** Change the SID password from it's MSID default
	 * @param newpassword  new password for SID and locking SP admins
	 */
	virtual uint8_t takeOwnership(const char* newpassword) = 0;
	/** Reset the TPER to its factory condition
     * ERASES ALL DATA!
     * @param authority selects the authority to use in the session
     * @param password password of authority (SID or PSID)
     * @param AdminSP set to 1 to use AdminSP instead of This for invokingID
     */
	virtual uint8_t revertTPer(const char* authority, const char* password,
                               const uint8_t AdminSP = 0) = 0;
    /** Revert the selected SP to factory state
     * @param sp security protocol to revert, Admin or Locking
     * @param authority Authority to use for thre session, SID or AdminX
     * @param password PIN for the authority
     * @param keep indicated if the global range Key should be kept
     */
    virtual uint8_t revertSP(const char* sp, const char* authority, const char* password,
                             const uint8_t keep) = 0;
	/** Erase a locking range
	 * @param lockingrange The number of the locking range (0 = global)
	 * @param password Password of administrative authority for locking range
	 */
	virtual uint8_t eraseLockingRange(const uint8_t lockingrange, const char* password) = 0;

	/** Assign a locking range to a Namespace
	 * @param authority authority to use for the session
	 * @param password Password of authority
	 * @param namespace
	 * @param global - bool, true for a global range
	 * @param start - N/A if global is true
	 * @param length - N/A if global is true
	 */
	virtual uint8_t assign(const char* authority, const char* password, const uint32_t ns,
	                       const uint64_t start = 0, const uint64_t length = 0, const uint32_t sum = 0) = 0;

	/** Deassign a locking range
	 * @param authority authority to use for the session
	 * @param password Password of authority
	 * @param lockingrange The number of the locking range
	 * @param keep True to keep the global range Key
	 */
	virtual uint8_t deassign(const char* authority, const char* password, const uint8_t lockingrange,
                             const bool keep) = 0;

	/** Dumps an object for diagnostic purposes
	 * @param sp index into the OPALUID table for the SP the object is in
	 * @param auth the authority to use for the dump
	 * @param pass the password for the authority
	 * @param objID the UID of the object to dump
	 */
	virtual uint8_t objDump(const char* sp, const char* auth, const char* pass,
                            const char* objID) = 0;
	/** Issue any command to the drive for diagnostic purposes
	 * @param sp index into the OPALUID table for the SP the object is in
	 * @param auth the authority to use for the dump
	 * @param pass the password for the authority
	 * @param invoker caller of the method
	 * @param method the method to call
	 * @param plist  the parameter list for the command
	 *
	 */
	virtual uint8_t rawCmd(const char* sp, const char* auth, const char* pass,
                           const char* invoker, const char* method, const char* plist) = 0;
	/** Read MSID
	 */
	virtual uint8_t printDefaultPassword() = 0;
	/** Print the tables supported by the TPER
	 */
	virtual uint8_t printTables(const char* sp, const char* password, const uint8_t level) = 0;

    /** Enables or disables TPER_RESET in the device as defined in TCG Opal specification
     * @param password SID password
     * @param options enable or disable
     */
    virtual uint8_t enableTperReset(const char* password, const uint8_t options) = 0;

    /** Enables or disables Programmic Reset in the MBR Control table as defined in TCG Opal specification
     * @param authority authority to use
     * @param password LockingSP Admin1 password
     * @param options enable or disable
     */
    virtual uint8_t clearDoneOnReset(const char* authority, const char* password, const uint8_t options) = 0;

    /** Get an ACE table entry booelan expression column value and print it
     * @param sp - security protocol
     * @param auth - authority to use
     * @param password - password for that authority
     * @param halfRow - least significant 32 bits of the ACE table row
     */
    virtual uint8_t getACE(const char* sp, const char* auth, const char* password, const uint32_t halfRow) = 0;

    /** Set and ACE table entry boolean expression column to a UID value (only 1)
     * @param sp - security protocol
     * @param auth - authority to use
     * @param password - password for that authority
     * @param halfRow - least significant 32 bits of the ACE table row
     * @param expression - user to set (i.e., Admins, Anybody, SID, Admin1, User1)
     */
    virtual uint8_t setACE(const char* sp, const char* auth, const char* password, const uint32_t halfRow,
                           const char* expression) = 0;

    /** Get a Random number
     * @param sp security protocol
     * @param authority authority to use when opening the session
     * @param password PIN for the authority
     * @param size number of bytes of random numner to request
     */
    virtual uint8_t getRandom(const char* sp, const char* authority, const char* password, const uint32_t size) = 0;

    /** Issues TPER_RESET to the device as defined in TCG Opal specification
     */
    uint8_t tperReset();

    /** Issues STACK_RESET to the device for the ComID used by sedutil
     */
    uint8_t stackReset();

	/*
	* virtual functions required to be implemented
	* because they are called by DtaSession.cpp
	*/
	/** Send a command to the device and wait for the response
	 * @param cmd the MswdCommand object containing the command
	 * @param response the DtaResonse object containing the response
	 * @param protocol The security protocol number to use for the command
	 */
	virtual uint8_t exec(const DtaCommand* cmd, DtaResponse& resp, const uint16_t ComID, const uint8_t protocol = 0x01) = 0;
	/** return the communications ID to be used for sessions to this device */
	virtual uint16_t comID() = 0;

    void GetExtendedComID(uint16_t* ComID, uint16_t* ComIDExtension);

    void OpenOutputFile();
    void CloseOutputFile();
    void SendToOutputFile(const uint8_t* data, const int count);

	bool no_hash_passwords; /** disables hashing of passwords */
	sedutiloutput output_format; /** standard, readable, JSON */
    uint32_t timeout = 0;   /** Session timeout, 0 is no timeout */
    uint32_t delay = 0;     /** Delay between open session and first method call */
    uint32_t sendRetries = 0;
    bool testTimeout = false;
    bool testOversizePacket = false;
    bool useTransaction = false;
    bool useReadOnlySession = false;
    bool useSessionTimeout = false;
    uint16_t ComIDValue = 0;
    uint16_t ComIDExtentionValue = 0;
    ComIDOption_t ComIDOption = ComID_Base;
    char * outputFileName = NULL;
    std::ofstream outputStream;

protected:
	const char * dev;   /**< character string representing the device in the OS lexicon */
	uint8_t isOpen = FALSE;  /**< The device has been opened */
	OPAL_DiskInfo disk_info;  /**< Structure containing info from identify and discovery 0 */
	DtaResponse response;   /**< shared response object */
	DtaResponse propertiesResponse;  /**< response fron properties exchange */
	DtaSession *session;  /**< shared session object pointer */
	uint8_t discovery0buffer[MIN_BUFFER_LENGTH + IO_BUFFER_ALIGNMENT];
	uint32_t tperMaxPacket = 2048;
	uint32_t tperMaxToken = 1950;
};
