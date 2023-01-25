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
#include <stdio.h>
#include "DtaSession.h"
#include "DtaOptions.h"
#include "DtaDev.h"
#include "DtaCommand.h"
#include "DtaResponse.h"
#include "DtaEndianFixup.h"
#include "DtaHexDump.h"
#include "DtaHashPwd.h"
#include "DtaStructures.h"

#include <thread>
#include <chrono>

using namespace std;

DtaSession::DtaSession(DtaDev * device)
{
    LOG(D1) << "Creating DtaSsession()";
    sessionauth = 0;
    d = device;

    d->GetExtendedComID(&ComID, &ComIDExtension);
}

uint8_t
DtaSession::start(const OPAL_UID SP)
{
    return (start(SP, NULL, OPAL_UID::OPAL_UID_HEXFF));
}

uint8_t 
DtaSession::start(const OPAL_UID SP, const char* HostChallenge, const OPAL_UID SignAuthority)
{
	LOG(D1) << "Entering DtaSession::startSession ";
	vector<uint8_t> auth;
	auth.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
	for (int i = 0; i < 8; i++) {
		auth.push_back(OPALUID[SignAuthority][i]);
	}
	return(start(SP, HostChallenge, auth));
}

uint8_t DtaSession::authuser() const
{
	return sessionauth;
}

#ifdef MULTISTART
uint8_t
DtaSession::start(const OPAL_UID SP, const char* HostChallenge, 
                  const std::vector<uint8_t>& SignAuthority)
{
	vector <uint8_t> auth;
	if ((lastRC = unistart(SP, HostChallenge, SignAuthority)) == 0) {
		sessionauth = 0;
		return 0;
	}
	else {
		for (uint8_t i = 1; i < 9; i++) {
			// { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x01 }, /**< USER1 */
			auth.clear();
			auth.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
			auth.push_back(0x00);
			auth.push_back(0x00);
			auth.push_back(0x00);
			auth.push_back(0x09);
			auth.push_back(0x00);
			auth.push_back(0x03);
			auth.push_back(0x00);
			auth.push_back(i);
			if ((lastRC = unistart(SP, HostChallenge, auth)) == 0) {
				sessionauth = i;
				return 0;
			}
		}
	}
	return lastRC;
}

uint8_t
DtaSession::unistart(const OPAL_UID SP, const char* HostChallenge, const std::vector<uint8_t>& SignAuthority)
#else
uint8_t
DtaSession::start(const OPAL_UID SP, const char* HostChallenge, const std::vector<uint8_t>& SignAuthority)
#endif
{
    LOG(D1) << "Entering DtaSession::startSession ";
	vector<uint8_t> hash;
	int settimeout = d->isEprise();
	lastRC = 0;

again:
    DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
    DtaResponse response;
    cmd->reset(OPAL_UID::OPAL_SMUID_UID, OPAL_METHOD::STARTSESSION);
    cmd->addToken(OPAL_TOKEN::STARTLIST); // [  (Open Bracket)
    cmd->addToken(105); // HostSessionID : sessionnumber
    cmd->addToken(SP); // SPID : SP
    cmd->addToken(d->useReadOnlySession ? OPAL_TINY_ATOM::UINT_00 : OPAL_TINY_ATOM::UINT_01); // ro/write
	if ((NULL != HostChallenge) && (!d->isEprise()) && (SignAuthority.size() != 0)) {
		cmd->addToken(OPAL_TOKEN::STARTNAME);
		cmd->addToken(OPAL_TINY_ATOM::UINT_00);
		if (hashPwd) {
			hash.clear();
			DtaHashPwd(hash, HostChallenge, d);
			cmd->addToken(hash);
		} else {
			cmd->addToken(HostChallenge);
		}
		cmd->addToken(OPAL_TOKEN::ENDNAME);
		cmd->addToken(OPAL_TOKEN::STARTNAME);
		cmd->addToken(OPAL_TINY_ATOM::UINT_03);
		cmd->addToken(SignAuthority);
		cmd->addToken(OPAL_TOKEN::ENDNAME);
	}
 
	// w/o the timeout the session may wedge and require a power-cycle,
	// e.g., when interrupted by ^C. 60 seconds is inconveniently long,
	// but revert may require that long to complete.
	if (settimeout) {
		cmd->addToken(OPAL_TOKEN::STARTNAME);
		cmd->addToken("SessionTimeout");
		cmd->addToken(60000);
		cmd->addToken(OPAL_TOKEN::ENDNAME);
	}
    else if (d->timeout) {
		cmd->addToken(OPAL_TOKEN::STARTNAME);
		cmd->addToken(OPAL_TINY_ATOM::UINT_05);
		cmd->addToken(d->timeout);
		cmd->addToken(OPAL_TOKEN::ENDNAME);
    }

    cmd->addToken(OPAL_TOKEN::ENDLIST); // ]  (Close Bracket)
    cmd->complete();
	if ((lastRC = sendCommand(cmd, response)) != 0) {
		delete cmd;
		if (settimeout) {
			LOG(D2) << "Session start with SessionTimeout parameter failed rc = " << (int)lastRC;
			settimeout = 0;
			goto again;
		}
		LOG(E) << "Session start failed rc = " << (int)lastRC;
		return lastRC;
	}  
    // call user method SL HSN TSN EL EOD SL 00 00 00 EL
    //   0   1     2     3  4   5   6  7   8
    HSN = SWAP32(response.getUint32(4));
    TSN = SWAP32(response.getUint32(5));
	delete cmd;
	if ((NULL != HostChallenge) && (d->isEprise())) {
		return(authenticate(SignAuthority, HostChallenge));
	}

    if (d->useTransaction) {
        DtaCommand *cmd = new DtaCommand();
        cmd->reset();
        cmd->addToken(OPAL_TOKEN::STARTTRANSACTON);
        cmd->addToken((uint64_t)0);
        cmd->complete(0);
        sendCommand(cmd, response);
        delete cmd;
    }

    if (d->testTimeout) {
        int64_t waitTime = d->delay;
        if (d->delay == 0) {
            // configure to test timeout.  Wait here for timeout + 2 seconds.
            waitTime = d->timeout + 2000;
        }
        LOG(W) << "Testing timeout, waiting " << waitTime << " milliseconds after opening the session";
        std::this_thread::sleep_for(std::chrono::milliseconds(waitTime));
    }

    return 0;
}

uint8_t
DtaSession::authenticate(const vector<uint8_t>& Authority, const char* Challenge)
{
	LOG(D1) << "Entering DtaSession::authenticate ";
	vector<uint8_t> hash;
	DtaCommand *cmd = new DtaCommand();
	if (NULL == cmd) {
		LOG(E) << "Unable to create session object ";
		return DTAERROR_OBJECT_CREATE_FAILED;
	}
	DtaResponse response;
	cmd->reset(OPAL_UID::OPAL_THISSP_UID, d->isEprise() ? OPAL_METHOD::EAUTHENTICATE : OPAL_METHOD::AUTHENTICATE);
	cmd->addToken(OPAL_TOKEN::STARTLIST); // [  (Open Bracket)
	cmd->addToken(Authority);
    if (Challenge && *Challenge)
    {
		cmd->addToken(OPAL_TOKEN::STARTNAME);
		if (d->isEprise())
			cmd->addToken("Challenge");
		else
			cmd->addToken(OPAL_TINY_ATOM::UINT_00);
		if (hashPwd) {
			hash.clear();
			DtaHashPwd(hash, Challenge, d);
			cmd->addToken(hash);
		}
		else
			cmd->addToken(Challenge);
		cmd->addToken(OPAL_TOKEN::ENDNAME);
    }
	cmd->addToken(OPAL_TOKEN::ENDLIST); // ]  (Close Bracket)
	cmd->complete();
	if ((lastRC = sendCommand(cmd, response)) != 0) {
		LOG(E) << "Session Authenticate failed";
		delete cmd;
		return lastRC;
	}
	if (0 == response.getUint8(1)) {
		LOG(E) << "Session Authenticate failed (response = false)";
		delete cmd;
		return DTAERROR_AUTH_FAILED;
	}

	LOG(D1) << "Exiting DtaSession::authenticate "; 
	delete cmd;
	return 0;
}

uint8_t
DtaSession::sendCommand(DtaCommand * cmd, DtaResponse & response)
{
    LOG(D1) << "Entering DtaSession::sendCommand()";
    cmd->setHSN(HSN);
    cmd->setTSN(TSN);
    cmd->setcomID(ComID, ComIDExtension);

    uint8_t exec_rc = d->exec(cmd, response, ComID, SecurityProtocol);
    if (0 != exec_rc)
    {
        LOG(E) << "Command failed on exec " << (uint16_t) exec_rc;
        return exec_rc;
    }
    /*
     * Check out the basics that so that we know we
     * have a sane reply to work with
     */
    // zero lengths -- these are big endian but it doesn't matter for uint = 0
    if ((0 == response.h.cp.outstandingData) &&
        (0 == response.h.cp.minTransfer) &&
        (0 == response.h.cp.length)) {
        LOG(D1) << "All Response(s) returned – no further data, request parsing error";
		return DTAERROR_COMMAND_ERROR;
    }
    if ((0 == response.h.cp.length) ||
        (0 == response.h.pkt.length) ||
        (0 == response.h.subpkt.length)) {
        LOG(E) << "One or more header fields have 0 length";
		return DTAERROR_COMMAND_ERROR;
    }
    // if we get an endsession response return 0
    OPAL_TOKEN token = response.tokenIs(0);
    if (OPAL_TOKEN::ENDOFSESSION == token) {
        return 0;
    }
    // if we got a Start Transaction or End Transaction, return transaction status
    if ((OPAL_TOKEN::STARTTRANSACTON == token) ||
        (OPAL_TOKEN::ENDTRANSACTON   == token )) {
        return response.getUint8(1);
    }
    // IF we received a method status return it
    if (!((OPAL_TOKEN::ENDLIST   == response.tokenIs(response.getTokenCount() - 1)) &&
          (OPAL_TOKEN::STARTLIST == response.tokenIs(response.getTokenCount() - 5)))) {
        // no method status so we hope we reported the error someplace else
        LOG(E) << "Method Status missing";
		return DTAERROR_NO_METHOD_STATUS;
    }
    if (OPALSTATUSCODE::SUCCESS != response.getUint8(response.getTokenCount() - 4)) {
        LOG(E) << "method status code " <<
                methodStatus(response.getUint8(response.getTokenCount() - 4));
    }

	// Check for a CloseSession response (indicates session was aborted by TPer)
	if (OPAL_TOKEN::CALL == token) {
		uint8_t invokingUID[32];
		uint8_t method[32];
		if ((response.getBytes(1, invokingUID) == 8) &&
		    (response.getBytes(2, method) == 8)) {
			if ((memcmp(invokingUID, OPALUID[OPAL_UID::OPAL_SMUID_UID],     8) == 0) &&
			    (memcmp(method,      OPALMETHOD[OPAL_METHOD::CLOSESESSION], 8) == 0)) {
				LOG(E) << "CloseSession response indicates the session was aborted by the Tper";
				return DTAERROR_SESSION_CLOSED;
			}
		}
	}

	return response.getUint8(response.getTokenCount() - 4);
}

void
DtaSession::setProtocol(const uint8_t value)
{
    LOG(D1) << "Entering DtaSession::setProtocol";
    SecurityProtocol = value;
}

void
DtaSession::dontHashPwd()
{
	LOG(D1) << "Entering DtaSession::dontHashPwd";
	hashPwd = 0;
}

void
DtaSession::expectAbort()
{
    LOG(D1) << "Entering DtaSession::expectAbort()";
    willAbort = 1;
}

const char*
DtaSession::methodStatus(const uint8_t status) const
{
    LOG(D1) << "Entering DtaSession::methodStatus()";
    switch (status) {
    case OPALSTATUSCODE::AUTHORITY_LOCKED_OUT:
        return "AUTHORITY_LOCKED_OUT";
    case OPALSTATUSCODE::FAIL:
        return "FAIL";
    case OPALSTATUSCODE::INSUFFICIENT_ROWS:
        return "INSUFFICIENT_ROWS";
    case OPALSTATUSCODE::INSUFFICIENT_SPACE:
        return "INSUFFICIENT_SPACE";
	case OPALSTATUSCODE::INVALID_FUNCTION:
		return "INVALID_FUNCTION";
    case OPALSTATUSCODE::INVALID_PARAMETER:
        return "INVALID_PARAMETER";
	case OPALSTATUSCODE::INVALID_REFERENCE:
		return "INVALID_REFERENCE";
    case OPALSTATUSCODE::NOT_AUTHORIZED:
        return "NOT_AUTHORIZED";
    case OPALSTATUSCODE::NO_SESSIONS_AVAILABLE:
        return "NO_SESSIONS_AVAILABLE";
    case OPALSTATUSCODE::RESPONSE_OVERFLOW:
        return "RESPONSE_OVERFLOW";
    case OPALSTATUSCODE::SP_BUSY:
        return "SP_BUSY";
    case OPALSTATUSCODE::SP_DISABLED:
        return "SP_DISABLED";
    case OPALSTATUSCODE::SP_FAILED:
        return "SP_FAILED";
    case OPALSTATUSCODE::SP_FROZEN:
        return "SP_FROZEN";
    case OPALSTATUSCODE::SUCCESS:
        return "SUCCESS";
    case OPALSTATUSCODE::TPER_MALFUNCTION:
        return "TPER_MALFUNCTION";
    case OPALSTATUSCODE::TRANSACTION_FAILURE:
        return "TRANSACTION_FAILURE";
    case OPALSTATUSCODE::UNIQUENESS_CONFLICT:
        return "UNIQUENESS_CONFLICT";
    default:
        return "Unknown status code";
    }
}

DtaSession::~DtaSession()
{
    LOG(D1) << "Destroying DtaSession";
	DtaResponse response;
    if (!willAbort) {
        DtaCommand *cmd = new DtaCommand();
		if (NULL == cmd) {
			LOG(E) << "Unable to create command object ";
		} 
		else {
            if (d->useTransaction) {
                cmd->reset();
                cmd->addToken(OPAL_TOKEN::ENDTRANSACTON);
                cmd->addToken((uint64_t)0);
                cmd->complete(0);
                if (sendCommand(cmd, response)) {
                    LOG(E) << "End Transaction Failed";
                }
            }
			cmd->reset();
			cmd->addToken(OPAL_TOKEN::ENDOFSESSION);
			cmd->complete(0);
			if (sendCommand(cmd, response)) {
				LOG(E) << "EndSession Failed";
			}
			delete cmd;
		}
    }
}
