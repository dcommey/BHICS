// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BHICSLog {
    event LogEntry(string eventType, string id, string data, uint256 timestamp);

    function log(string memory eventType, string memory id, string memory data) public {
        emit LogEntry(eventType, id, data, block.timestamp);
    }
}