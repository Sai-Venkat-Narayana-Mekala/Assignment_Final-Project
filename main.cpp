#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <bitset>
#include <string>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <algorithm>
#include <cctype>

// Setting up initial hash values for SHA-256
uint32_t initialHash0 = 0x6a09e667; // Starting hash value H0
uint32_t initialHash1 = 0xbb67ae85; // Starting hash value H1
uint32_t initialHash2 = 0x3c6ef372; // Starting hash value H2
uint32_t initialHash3 = 0xa54ff53a; // Starting hash value H3
uint32_t initialHash4 = 0x510e527f; // Starting hash value H4
uint32_t initialHash5 = 0x9b05688c; // Starting hash value H5
uint32_t initialHash6 = 0x1f83d9ab; // Starting hash value H6
uint32_t initialHash7 = 0x5be0cd19; // Starting hash value H7

// Constants used in SHA-256 compression function
uint32_t sha256Constants[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Function that rotates bits to the right for a 32-bit integer
uint32_t performRightRotate(uint32_t value, unsigned int shift) {
    // Shifts bits to the right and wraps the shifted bits to the left
    return (value >> shift) | (value << (32 - shift));
}

// Function that processes the message schedule with SHA-256 compression
void performSha256Compression(uint32_t *scheduleArray) {
    // Setting up working variables using current hash values
    uint32_t tempA = initialHash0;
    uint32_t tempB = initialHash1;
    uint32_t tempC = initialHash2;
    uint32_t tempD = initialHash3;
    uint32_t tempE = initialHash4;
    uint32_t tempF = initialHash5;
    uint32_t tempG = initialHash6;
    uint32_t tempH = initialHash7;

    // Looping through each message schedule word
    for (int i = 0; i < 64; ++i) {
        // Calculating message schedule values with bitwise operations
        uint32_t s1 = performRightRotate(tempE, 6) ^ performRightRotate(tempE, 11) ^ performRightRotate(tempE, 25);
        uint32_t ch = (tempE & tempF) ^ (~tempE & tempG);
        uint32_t temp1 = tempH + s1 + ch + sha256Constants[i] + scheduleArray[i];
        uint32_t s0 = performRightRotate(tempA, 2) ^ performRightRotate(tempA, 13) ^ performRightRotate(tempA, 22);
        uint32_t maj = (tempA & tempB) ^ (tempA & tempC) ^ (tempB & tempC);
        uint32_t temp2 = s0 + maj;

        // Updating hash values based on computed results
        tempH = tempG;
        tempG = tempF;
        tempF = tempE;
        tempE = tempD + temp1;
        tempD = tempC;
        tempC = tempB;
        tempB = tempA;
        tempA = temp1 + temp2;
    }

    // Adding computed values to the current hash values
    initialHash0 += tempA;
    initialHash1 += tempB;
    initialHash2 += tempC;
    initialHash3 += tempD;
    initialHash4 += tempE;
    initialHash5 += tempF;
    initialHash6 += tempG;
    initialHash7 += tempH;
}

// Function to create a SHA-256 hash from a given input string
std::string generateSha256Hash(const std::string &textInput) {
    // Converting input string into a byte vector
    std::vector<uint8_t> messageBuffer(textInput.begin(), textInput.end());

    uint64_t bitLength = messageBuffer.size() * 8; // Determining the bit length of the message

    // Appending a single '1' bit to the message
    messageBuffer.push_back(0x80);

    // Padding the message with zeros until its length is 56 modulo 64
    while (messageBuffer.size() % 64 != 56) {
        messageBuffer.push_back(0x00);
    }

    // Adding the original message length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        messageBuffer.push_back((bitLength >> (i * 8)) & 0xff);
    }

    // Processing each 512-bit chunk of the message
    for (size_t offset = 0; offset < messageBuffer.size(); offset += 64) {
        uint32_t messageSchedule[64] = {0};

        // Loading the first 16 words of the chunk into the message schedule
        for (int j = 0; j < 16; ++j) {
            messageSchedule[j] = (messageBuffer[offset + 4 * j] << 24) | (messageBuffer[offset + 4 * j + 1] << 16) |
                                 (messageBuffer[offset + 4 * j + 2] << 8) | (messageBuffer[offset + 4 * j + 3]);
        }

        // Extending the first 16 words to fill the remaining 48 words of the message schedule
        for (int j = 16; j < 64; ++j) {
            uint32_t s0 = performRightRotate(messageSchedule[j - 15], 7) ^ performRightRotate(messageSchedule[j - 15], 18) ^ (messageSchedule[j - 15] >> 3);
            uint32_t s1 = performRightRotate(messageSchedule[j - 2], 17) ^ performRightRotate(messageSchedule[j - 2], 19) ^ (messageSchedule[j - 2] >> 10);
            messageSchedule[j] = messageSchedule[j - 16] + s0 + messageSchedule[j - 7] + s1;
        }

        // Applying SHA-256 compression to the message schedule
        performSha256Compression(messageSchedule);
    }

    // Creating the final SHA-256 hash as a hexadecimal string
    std::stringstream hashStream;
    hashStream << std::hex << std::setfill('0') << std::setw(8) << initialHash0
               << std::setw(8) << initialHash1 << std::setw(8) << initialHash2
               << std::setw(8) << initialHash3 << std::setw(8) << initialHash4
               << std::setw(8) << initialHash5 << std::setw(8) << initialHash6
               << std::setw(8) << initialHash7;

    return hashStream.str();
}

// Function to prepare and clean input text for hashing
std::string preprocessAndCleanText(const std::string &inputText) {
    std::string cleanedText = inputText;

    // Removing text enclosed in square brackets, such as footnotes or citations
    std::string::size_type startPos = 0;
    while ((startPos = cleanedText.find('[')) != std::string::npos) {
        std::string::size_type endPos = cleanedText.find(']', startPos);
        if (endPos != std::string::npos) {
            cleanedText.erase(startPos, endPos - startPos + 1);
        } else {
            break;
        }
    }

    // Eliminating non-alphanumeric and non-whitespace characters
    cleanedText.erase(std::remove_if(cleanedText.begin(), cleanedText.end(), [](unsigned char ch) {
        return !std::isalnum(ch) && !std::isspace(ch);
    }), cleanedText.end());

    // Trimming leading and trailing whitespace and normalizing newlines
    cleanedText.erase(cleanedText.begin(), std::find_if(cleanedText.begin(), cleanedText.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    cleanedText.erase(std::find_if(cleanedText.rbegin(), cleanedText.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), cleanedText.end());
    std::replace(cleanedText.begin(), cleanedText.end(), '\r', '\n');

    return cleanedText;
}

int main() {
    // Loading the file with the Book of Mark's text
    std::ifstream markFile("mark.txt");
    if (!markFile) {
        std::cerr << "File cannot be opened!" << std::endl;
        return 1;
    }

    // Reading the file content into a string
    std::string markText((std::istreambuf_iterator<char>(markFile)), std::istreambuf_iterator<char>());
    markFile.close();

    // Preparing and cleaning the text for hashing
    markText = preprocessAndCleanText(markText);

    std::cout << "Text before hashing:\n" << markText << std::endl;

    // Generating the SHA-256 hash of the cleaned text
    std::string sha256Hash = generateSha256Hash(markText);

    std::cout << "SHA-256 hash of the book of Mark: " << sha256Hash << std::endl;

    return 0;
}
