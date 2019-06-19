#pragma once
/** 
 * Base64 encoding
 * taken from various places on the web
 * by AJHL
 * written to be C++11 compliant, columnwidth = 90
 */

#include<string>
#include<vector>

namespace philips {

/*--------------------------------------------------------------------------------------
 * BASE 64
 *-------------------------------------------------------------------------------------*/

// base_64 by elegant dice on stackoverlow
void base64_encode(std::string& out, const std::vector<uint8_t>& buf);
void base64_encode(std::string& out, uint8_t const * buf, size_t bufLen);
void base64_encode(std::string& out, const std::string & buf);

void base64_decode(std::vector<uint8_t>& out, const std::string& encoded_string);
void base64_decode(std::string& out, const std::string& encoded_string);

}

